// SPDX-License-Identifier: BSD-2-Clause
// Copyright © 2021 Billy Laws

#include <vulkan/vulkan.h>
#include <fstream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <android/api-level.h>
#include <android/log.h>
#include <android_linker_ns.h>
#include "hook/kgsl.h"
#include "hook/hook_impl_params.h"
#include <adrenotools/driver.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <pwd.h>
#include <cstring>
#include <jni.h>
#include <shadowhook.h>
#include <atomic>
#include <pthread.h>
#include <vector>
#include <mutex>
#include <bytehook.h>
#include <sys/resource.h>
#include <sys/system_properties.h>
#include <iostream>
#include <android/dlext.h>

#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO,  "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN,  "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, "AdrenoToolsPatch", __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
//  Global driver state
// ─────────────────────────────────────────────────────────────────────────────
static PFN_vkGetInstanceProcAddr gipa_stub      = nullptr;
static PFN_vkGetDeviceProcAddr   gdpa_stub      = nullptr;

static std::mutex                g_init_mutex;
static void                     *g_turnip_handle = nullptr;
static PFN_vkGetInstanceProcAddr g_turnip_gipa   = nullptr;
static PFN_vkGetDeviceProcAddr   g_turnip_gdpa   = nullptr;
static std::once_flag            g_init_flag;
static JavaVM                   *g_java_vm        = nullptr;
static struct prop_info {} mesa_prop_info;

static constexpr const char *kOwnedEnvVars[] = {
    // Mesa / ICD
    "MESA_VULKAN_ICD_SELECT",
    "MESA_VK_IGNORE_CONFORMANCE_WARNING",
    "MESA_VK_DEVICE_SELECT_FORCE_DEFAULT_DEVICE",
    "MESA_VK_VERSION_OVERRIDE",
    "MESA_VK_WSI_PRESENT_MODE",
    "MESA_VK_CACHE_CONTROL",
    // Shader cache
    "MESA_GLSL_CACHE_DISABLE",
    "MESA_GLSL_CACHE_MAX_SIZE",
    // Mesa debug / error
    "MESA_DEBUG",
    "MESA_NO_ERROR",
    "GALLIUM_PRINT_OPTIONS",
    // Turnip-specific
    "TU_DEBUG",
    "TU_ROBUST_BUFFER_ACCESS",
    "TU_OVERRIDE_HEAP_SIZE",
    // Freedreno / device features
    "FD_DEV_FEATURES",
    // KGSL / display
    "KGSL_CONTEXT_PRIORITY",
    "ADRENO_TURBO",
    "vblank_mode",
    // GL thread
    "mesa_glthread",
    // Unity integration
    "UNITY_DISABLE_GRAPHICS_DRIVER_CHECK",
    "UNITY_VULKAN_ENABLE_VALIDATION_LAYERS",
    "UNITY_GFX_DEVICE_API",
    // unused but on old updates 
    "TU_INDIRECT_DRAW_THRESHOLD",
    "MESA_VK_DESCRIPTOR_POOL_TEMP",
    "MESA_VK_ABORT_ON_DEVICE_LOSS",
    "TU_FORCE_ANISO"
};

// ─────────────────────────────────────────────────────────────────────────────
//  Adreno generation helpers
// ─────────────────────────────────────────────────────────────────────────────
enum class AdrenoGen { UNKNOWN, A5xx, A6xx, A7xx, A8xx };

static AdrenoGen detect_adreno_gen(const std::string &name) {
    if (name.find("Adreno (TM) 8") != std::string::npos) return AdrenoGen::A8xx;
    if (name.find("Adreno (TM) 7") != std::string::npos) return AdrenoGen::A7xx;
    if (name.find("Adreno (TM) 6") != std::string::npos) return AdrenoGen::A6xx;
    if (name.find("Adreno (TM) 5") != std::string::npos) return AdrenoGen::A5xx;
    return AdrenoGen::UNKNOWN;
}

// ─────────────────────────────────────────────────────────────────────────────
//  adrenotools_open_libvulkan
// ─────────────────────────────────────────────────────────────────────────────
void *adrenotools_open_libvulkan(int dlopenFlags, int featureFlags, const char *tmpLibDir, const char *hookLibDir, const char *customDriverDir, const char *customDriverName, const char *fileRedirectDir, void **userMappingHandle) {
    if (!linkernsbypass_load_status()) {
        ALOGE("FAILURE: Could not load linkernsbypass");
        return nullptr;
    }

    if (android_get_device_api_level() >= 29 && !tmpLibDir)
        tmpLibDir = nullptr;
    
    if ((featureFlags & ADRENOTOOLS_DRIVER_FILE_REDIRECT) && !fileRedirectDir) {
        ALOGE("FAILURE: ADRENOTOOLS_DRIVER_FILE_REDIRECT set but no fileRedirectDir provided");
        return nullptr;
    }

    if ((featureFlags & ADRENOTOOLS_DRIVER_CUSTOM) && (!customDriverDir || !customDriverName)) {
        ALOGE("FAILURE: ADRENOTOOLS_DRIVER_CUSTOM set but customDriverDir/customDriverName missing");
        return nullptr;
    }

    if ((featureFlags & ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT) && !userMappingHandle) {
        ALOGE("FAILURE: ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT set but userMappingHandle is null");
        return nullptr;
    }

    struct stat buf{};

    if (featureFlags & ADRENOTOOLS_DRIVER_CUSTOM) {
        if (stat((std::string(customDriverDir) + customDriverName).c_str(), &buf) != 0) {
            ALOGE("FAILURE: ADRENOTOOLS_DRIVER_CUSTOM set but driver file doesn't exist at %s%s", customDriverDir, customDriverName);
            return nullptr;
        }
    }

    if (featureFlags & ADRENOTOOLS_DRIVER_FILE_REDIRECT) {
        if (stat(fileRedirectDir, &buf) != 0) {
            ALOGE("FAILURE: ADRENOTOOLS_DRIVER_FILE_REDIRECT set but redirect dir doesn't exist: %s", fileRedirectDir);
            return nullptr;
        }
    }

    auto hookNs{android_create_namespace("adrenotools-libvulkan", hookLibDir, nullptr, ANDROID_NAMESPACE_TYPE_SHARED, nullptr, nullptr)};

    if (!linkernsbypass_link_namespace_to_default_all_libs(hookNs))
        return nullptr;

    auto hookImpl{linkernsbypass_namespace_dlopen("libhook_impl.so", RTLD_NOW, hookNs)};
    if (!hookImpl) {
        ALOGE("FAILURE: Couldn't preload the hook implementation");
        return nullptr;
    }

    auto initHookParam{reinterpret_cast<void (*)(const void *)>(dlsym(hookImpl, "init_hook_param"))};
    if (!initHookParam) {
        ALOGE("FAILURE: Couldn't init hook params");
        return nullptr;
    }

    auto importMapping{[&]() -> adrenotools_gpu_mapping * {
        if (featureFlags & ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT) {
            auto *mapping = new adrenotools_gpu_mapping{};
            *userMappingHandle = mapping;
            return mapping;
        }
        ALOGW("WARN: Memory mapping flag was not specified");
        return nullptr;
    }()};

    initHookParam(new HookImplParams(featureFlags, tmpLibDir, hookLibDir, customDriverDir, customDriverName, fileRedirectDir, importMapping));

    if (!linkernsbypass_namespace_dlopen("libmain_hook.so", RTLD_GLOBAL, hookNs)) {
        ALOGE("FAILURE: Failed to load libmain_hook into the isolated namespace");
        return nullptr;
    }

    return linkernsbypass_namespace_dlopen_unique("/system/lib64/libvulkan.so", tmpLibDir, dlopenFlags, hookNs);
}

// ─────────────────────────────────────────────────────────────────────────────
//  GPU memory helpers
// ─────────────────────────────────────────────────────────────────────────────
bool adrenotools_import_user_mem(void *handle, void *hostPtr, uint64_t size) {
    auto importMapping{reinterpret_cast<adrenotools_gpu_mapping *>(handle)};

    kgsl_gpuobj_import_useraddr addr{
        .virtaddr = reinterpret_cast<uint64_t>(hostPtr),
    };

    kgsl_gpuobj_import userMemImport{};
    userMemImport.priv     = reinterpret_cast<uint64_t>(&addr);
    userMemImport.priv_len = size;
    userMemImport.flags    = KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT
                           | KGSL_MEMFLAGS_IOCOHERENT;
    userMemImport.type     = KGSL_USER_MEM_TYPE_ADDR;

    kgsl_gpuobj_info info{};

    int kgslFd{open("/dev/kgsl-3d0", O_RDWR)};
    if (kgslFd < 0)
        return false;

    int ret{ioctl(kgslFd, IOCTL_KGSL_GPUOBJ_IMPORT, &userMemImport)};
    if (ret) { close(kgslFd); return false; }

    info.id = userMemImport.id;
    ret = ioctl(kgslFd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    if (ret) { close(kgslFd); return false; }

    importMapping->host_ptr = hostPtr;
    importMapping->gpu_addr = info.gpuaddr;
    importMapping->size     = size;
    importMapping->flags    = 0xc2600;

    close(kgslFd);
    return true;
}

bool adrenotools_mem_gpu_allocate(void *handle, uint64_t *size) {
    auto mapping{reinterpret_cast<adrenotools_gpu_mapping *>(handle)};

    kgsl_gpuobj_alloc gpuobjAlloc{};
    gpuobjAlloc.size  = *size;
    gpuobjAlloc.flags = KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT | KGSL_MEMFLAGS_IOCOHERENT;

    kgsl_gpuobj_info info{};

    int kgslFd{open("/dev/kgsl-3d0", O_RDWR)};
    if (kgslFd < 0)
        return false;

    int ret{ioctl(kgslFd, IOCTL_KGSL_GPUOBJ_ALLOC, &gpuobjAlloc)};
    if (ret) { close(kgslFd); return false; }

    *size = gpuobjAlloc.mmapsize;

    info.id = gpuobjAlloc.id;
    ret = ioctl(kgslFd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    if (ret) { close(kgslFd); return false; }

    mapping->host_ptr = nullptr;
    mapping->gpu_addr = info.gpuaddr;
    mapping->size     = *size;
    mapping->flags    = 0xc2600;

    close(kgslFd);
    return true;
}

bool adrenotools_mem_cpu_map(void *handle, void *hostPtr, uint64_t size) {
    auto mapping{reinterpret_cast<adrenotools_gpu_mapping *>(handle)};

    int kgslFd{open("/dev/kgsl-3d0", O_RDWR)};
    if (kgslFd < 0)
        return false;

    mapping->host_ptr = mmap(hostPtr, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kgslFd, mapping->gpu_addr);
    close(kgslFd);
    return mapping->host_ptr != nullptr;
}

bool adrenotools_validate_gpu_mapping(void *handle) {
    auto importMapping{reinterpret_cast<adrenotools_gpu_mapping *>(handle)};
    return importMapping->gpu_addr == ADRENOTOOLS_GPU_MAPPING_SUCCEEDED_MAGIC;
}

void adrenotools_set_turbo(bool turbo) {
    uint32_t enable{turbo ? 0U : 1U};
    kgsl_device_getproperty prop{
        .type      = KGSL_PROP_PWRCTRL,
        .value     = reinterpret_cast<void *>(&enable),
        .sizebytes = sizeof(enable),
    };

    int kgslFd{open("/dev/kgsl-3d0", O_RDWR)};
    if (kgslFd < 0)
        return;

    ioctl(kgslFd, IOCTL_KGSL_SETPROPERTY, &prop);
    close(kgslFd);
}

bool adrenotools_set_freedreno_env(const char *varName, const char *value) {
    if (!varName || !value || std::strlen(varName) == 0)
        return false;

    if (setenv(varName, value, 1) != 0) {
        ALOGE("FAILURE adrenotools_set_freedreno_env: Failed to set '%s' (errno: %d)", varName, errno);
        return false;
    }

    const char *verify = std::getenv(varName);
    if (verify && std::strcmp(verify, value) == 0)
        return true;

    ALOGW("WARN adrenotools_set_freedreno_env: Verification failed for '%s'", varName);
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Vulkan hook trampolines
// ─────────────────────────────────────────────────────────────────────────────
static PFN_vkVoidFunction hooked_vkGetInstanceProcAddr(VkInstance instance, const char *pName) {
    if (g_turnip_gipa) {
        auto func = g_turnip_gipa(instance, pName);
        if (func) return func;
    }
    return gipa_stub ? gipa_stub(instance, pName) : nullptr;
}

static PFN_vkVoidFunction hooked_vkGetDeviceProcAddr(VkDevice device, const char *pName) {
    if (g_turnip_gdpa) {
        auto func = g_turnip_gdpa(device, pName);
        if (func) return func;
    }
    return gdpa_stub ? gdpa_stub(device, pName) : nullptr;
}

static const prop_info *my_system_property_find(const char *name) {
    if (name && strncmp(name, "vendor.mesa.", 12) == 0) {
        return &mesa_prop_info;
    }
    
    return (const prop_info *)BYTEHOOK_CALL_PREV(my_system_property_find, name);
}

static int my_system_property_get(const char *name, char *value) {
    if (name && strncmp(name, "vendor.mesa.", 12) == 0) {
        if (strcmp(name, "vendor.mesa.driver") == 0) {
            strcpy(value, "msm");
            return 3;
        }
        if (strcmp(name, "vendor.mesa.gralloc") == 0) {
            strcpy(value, "gralloc4");
            return 8;
        }
        
        value[0] = '\0';
        return 0;
    }
    return BYTEHOOK_CALL_PREV(my_system_property_get, name, value);
}

// ─────────────────────────────────────────────────────────────────────────────
//  JNI helper
// ─────────────────────────────────────────────────────────────────────────────
static char *get_native_library_dir(JNIEnv *env, jobject context) {
    if (!context) return nullptr;

    jclass  contextClass = env->FindClass("android/content/Context");
    jmethodID getAppInfo = env->GetMethodID(contextClass, "getApplicationInfo",
                                             "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo      = env->CallObjectMethod(context, getAppInfo);

    jclass    appInfoClass = env->GetObjectClass(appInfo);
    jfieldID  fieldId      = env->GetFieldID(appInfoClass, "nativeLibraryDir",
                                              "Ljava/lang/String;");
    jstring   jPath        = (jstring)env->GetObjectField(appInfo, fieldId);

    char *result = nullptr;
    if (jPath) {
        const char *chars = env->GetStringUTFChars(jPath, nullptr);
        if (chars) {
            result = strdup(chars);
            env->ReleaseStringUTFChars(jPath, chars);
        }
        env->DeleteLocalRef(jPath);
    }

    env->DeleteLocalRef(appInfoClass);
    env->DeleteLocalRef(appInfo);
    env->DeleteLocalRef(contextClass);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Per-GPU TU_DEBUG tuning
// ─────────────────────────────────────────────────────────────────────────────
void applyTurnipOptimizations() {
    void *libvulkan = dlopen("libvulkan.so", RTLD_NOW);
    if (!libvulkan) return;

    auto pfnCreateInstance =
        (PFN_vkCreateInstance)dlsym(libvulkan, "vkCreateInstance");
    auto pfnEnumeratePhysicalDevices =
        (PFN_vkEnumeratePhysicalDevices)dlsym(libvulkan, "vkEnumeratePhysicalDevices");
    auto pfnGetPhysicalDeviceProperties =
        (PFN_vkGetPhysicalDeviceProperties)dlsym(libvulkan, "vkGetPhysicalDeviceProperties");
    auto pfnDestroyInstance =
        (PFN_vkDestroyInstance)dlsym(libvulkan, "vkDestroyInstance");

    if (!pfnCreateInstance || !pfnEnumeratePhysicalDevices ||
        !pfnGetPhysicalDeviceProperties || !pfnDestroyInstance) {
        dlclose(libvulkan);
        return;
    }

    VkInstance tempInstance       = VK_NULL_HANDLE;
    VkInstanceCreateInfo ci       = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};

    if (pfnCreateInstance(&ci, nullptr, &tempInstance) == VK_SUCCESS) {
        uint32_t count = 0;
        pfnEnumeratePhysicalDevices(tempInstance, &count, nullptr);

        if (count > 0) {
            std::vector<VkPhysicalDevice> devices(count);
            pfnEnumeratePhysicalDevices(tempInstance, &count, devices.data());

            VkPhysicalDeviceProperties props{};
            pfnGetPhysicalDeviceProperties(devices[0], &props);

            std::string name(props.deviceName);
            ALOGI("Detected GPU: %s", name.c_str());

            AdrenoGen gen = detect_adreno_gen(name);

            switch (gen) {
                case AdrenoGen::A8xx:
                    // A8xx has large GMEM — so no sysmem under clock
                    setenv("TU_DEBUG", "gmem,noconfirm,noflushall,lowprecision", 1);
                    ALOGI("A8xx: gmem rendering enabled");
                    ALOGI("UBWC: Enabling UBWC hint You are using A7xx");
                    setenv("FD_DEV_FEATURES", "enable_tp_ubwc_flag_hint=1", 1);
                    break;

                case AdrenoGen::A7xx:
                    // A7xx: gmem benefits in overclock; sysmem is cooler at stock.
               #ifdef OVERCLOCK
                    setenv("TU_DEBUG", "gmem,noconfirm,noflushall,lowprecision", 1);
                    ALOGI("A7xx OC: gmem rendering");
               #else
                    setenv("TU_DEBUG", "sysmem,noconfirm,noflushall,lowprecision", 1);
                    ALOGI("A7xx stock: sysmem rendering");
               #endif
                    ALOGI("UBWC: Enabling UBWC hint You are using A7xx");
                    setenv("FD_DEV_FEATURES", "enable_tp_ubwc_flag_hint=1", 1);
                    break;

                case AdrenoGen::A6xx:
                    setenv("TU_DEBUG", "sysmem,noconfirm,noflushall,lowprecision", 1);
                    ALOGI("A6xx: sysmem rendering");
                    ALOGI("UBWC: GPU safe No hint required");
                    break;

                case AdrenoGen::A5xx:
                    // A5xx: no UBWC, no reliable LRZ
                    setenv("TU_DEBUG", "sysmem,noconfirm,nolrz,noubwc", 1);
                    setenv("FD_DEV_FEATURES", "", 1);   // clear UBWC hint, not supported
                    ALOGW("A5xx: conservative sysmem, UBWC disabled");
                    break;

                default:
                    setenv("TU_DEBUG", "sysmem,noconfirm,noflushall,lowprecision,nolrz", 1);
                    ALOGW("Unknown Adreno gen: safe fallback");
                    break;
            }
        }

        pfnDestroyInstance(tempInstance, nullptr);
    }

    dlclose(libvulkan);
}

static void apply_sdk_tunables() {
    char sdk_str[8] = {};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    ALOGI("Android SDK: %d", sdk);

    if (sdk >= 34) {
        ALOGI("Android 14+ detected: skipping Vulkan version override");
    } else if (sdk >= 32) {
        setenv("MESA_VK_VERSION_OVERRIDE", "1.3", 1);
        ALOGI("Android 12L/13: forcing Vulkan 1.3 via override");
    } else if (sdk >= 31) {
        setenv("MESA_VK_VERSION_OVERRIDE", "1.2", 1);
        ALOGI("Android 9-12: forcing Vulkan 1.2 via override");
    } else {
        setenv("MESA_VK_VERSION_OVERRIDE", "1.1", 1);
        ALOGI("Android <9: forcing Vulkan 1.1 via override");
    }

    char oneui_str[PROP_VALUE_MAX] = {0};
    bool is_affected_oneui = false;
    
    if (__system_property_get("ro.build.version.oneui", oneui_str) > 0) {
        int raw_version = atoi(oneui_str);
        
        // Target One UI 6.0 (60000) and newer versions like One UI 7 (70000)
        if (raw_version >= 60000) {
            is_affected_oneui = true;
            int major = raw_version / 10000;
            int minor = (raw_version % 10000) / 100;
            ALOGI("Targeted One UI version detected: %d.%d", major, minor);
        }
    }

    // Apply UBWC fix ONLY if it is an affected One UI version on Android 11+
    if (is_affected_oneui && sdk >= 30) {
        setenv("FD_DEV_FEATURES", "enable_tp_ubwc_flag_hint=1", 1);
        ALOGI("One UI 6.0+: UBWC flag hint enabled to prevent texture glitches");
    } else {
        ALOGI("UBWC: Device Check  Completed Has no UBWC issues, checking GPU");
    }

#ifdef OVERCLOCK
    ALOGI("Overclock mode: no TU_OVERRIDE_HEAP_SIZE cap");
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    long long total_ram_bytes = (long long)pages * page_size;
    
    long heap_size_mb = (total_ram_bytes / (1024 * 1024)) / 2;
    
    if (heap_size_mb < 256) {
        heap_size_mb = 256;
    }

    char heap_str[16];
    snprintf(heap_str, sizeof(heap_str), "%ld", heap_size_mb);
    
    setenv("TU_OVERRIDE_HEAP_SIZE", heap_str, 1);
    ALOGI("Set TU_OVERRIDE_HEAP_SIZE to %s MB based on system RAM", heap_str);
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor — sets settings and runs before any hooks
// ─────────────────────────────────────────────────────────────────────────────
__attribute__((constructor))
static void global_atomic_init() {
    for (const char *var : kOwnedEnvVars) {
        if (unsetenv(var) != 0)
            ALOGW("unsetenv('%s') failed (errno %d)", var, errno);
    }
    // Mesa ICD / driver selection
    setenv("MESA_VULKAN_ICD_SELECT",              "turnip",  1);
    setenv("MESA_VK_IGNORE_CONFORMANCE_WARNING",  "true",    1);
    setenv("MESA_VK_DEVICE_SELECT_FORCE_DEFAULT_DEVICE", "1", 1);
    // Shader cache
    setenv("MESA_GLSL_CACHE_DISABLE",  "false", 1);
    setenv("MESA_GLSL_CACHE_MAX_SIZE", "512M",  1);
    setenv("MESA_VK_CACHE_CONTROL",    "1",     1);
    // Suppress noise
    setenv("GALLIUM_PRINT_OPTIONS", "0",      1);
    setenv("MESA_DEBUG",            "silent", 1);
    setenv("MESA_NO_ERROR",         "1",      1);
    setenv("TU_ROBUST_BUFFER_ACCESS", "0",   1);
	// fix gallium
	setenv("MESA_GRALLOC_API", "gralloc4", 1);
    setenv("MESA_EXTENSION_OVERRIDE", "-VK_KHR_external_memory_fd", 1);

#ifdef OVERCLOCK
    setenv("KGSL_CONTEXT_PRIORITY",  "1",       1);
    setenv("mesa_glthread",          "true",    1);
    setenv("ADRENO_TURBO",           "1",       1);
    setenv("vblank_mode",            "0",       1);
    setenv("MESA_VK_WSI_PRESENT_MODE", "mailbox", 1);
#else
    setenv("KGSL_CONTEXT_PRIORITY",  "2",    1);
    setenv("mesa_glthread",          "false", 1);
    setenv("ADRENO_TURBO",           "0",    1);
    setenv("vblank_mode",            "1",    1);
    setenv("MESA_VK_WSI_PRESENT_MODE", "fifo", 1);
#endif
    // Unity integration
    setenv("UNITY_DISABLE_GRAPHICS_DRIVER_CHECK",   "1",      1);
    setenv("UNITY_VULKAN_ENABLE_VALIDATION_LAYERS",  "0",      1);
    setenv("UNITY_GFX_DEVICE_API",                  "vulkan", 1);
    // SDK-aware tunables (Vulkan version override, UBWC, heap)
    apply_sdk_tunables();
    // Per-GPU TU_DEBUG flags
    applyTurnipOptimizations();

    shadowhook_init(SHADOWHOOK_MODE_SHARED, true);
	bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Turnip driver initialisation
// ─────────────────────────────────────────────────────────────────────────────
static void init_turnip_driver(JNIEnv *env, jobject context) {
    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_turnip_handle != nullptr) {
        ALOGI("init_turnip_driver: already initialised, skipping");
        return;
    }

    // ── gather paths ──────────────────────────────────────────────────────────
    char *native_lib_dir = get_native_library_dir(env, context);
    if (!native_lib_dir) {
        ALOGE("init_turnip_driver: could not get nativeLibraryDir");
        return;
    }

    char fixed_dir[512];
    snprintf(fixed_dir, sizeof(fixed_dir), "%s/", native_lib_dir);
    ALOGI("Native lib dir: %s", fixed_dir);
	setenv("VK_ICD_FILENAMES", fixed_dir, 1);

    setenv("MESA_LIBGL_DRIVERS_PATH", fixed_dir, 1);
    
    jclass    contextClass   = env->GetObjectClass(context);
    jmethodID getCacheDir    = env->GetMethodID(contextClass, "getCacheDir",
                                                 "()Ljava/io/File;");
    jobject   cacheFileObj   = env->CallObjectMethod(context, getCacheDir);
    jclass    fileClass      = env->GetObjectClass(cacheFileObj);
    jmethodID getAbsPath     = env->GetMethodID(fileClass, "getAbsolutePath",
                                                 "()Ljava/lang/String;");
    jstring   jPath          = (jstring)env->CallObjectMethod(cacheFileObj, getAbsPath);

    const char *base_cache_path = env->GetStringUTFChars(jPath, nullptr);

    char tmpdir[512];
    snprintf(tmpdir, sizeof(tmpdir), "%s/turnip_tmp/", base_cache_path);
    mkdir(tmpdir, 0775);
    
    char cache_dir[512];
    snprintf(cache_dir, sizeof(cache_dir), "%s/turnip_shader_cache/", base_cache_path);
    mkdir(cache_dir, 0775);
    setenv("MESA_DISK_CACHE_DIR", cache_dir, 1);
    ALOGI("Shader cache: %s", cache_dir);

    // ── load Turnip ───────────────────────────────────────────────────────────
    g_turnip_handle = adrenotools_open_libvulkan(
        RTLD_GLOBAL | RTLD_NOW,
        ADRENOTOOLS_DRIVER_CUSTOM,
        tmpdir,
        native_lib_dir,
        fixed_dir,
        "libvulkan_freedreno.so",
        nullptr,
        nullptr
    );

    if (!g_turnip_handle) {
        ALOGE("Failed to load Turnip via adrenotools — falling back to system Vulkan");
        goto cleanup;
    }

    g_turnip_gipa = (PFN_vkGetInstanceProcAddr)dlsym(g_turnip_handle, "vkGetInstanceProcAddr");
    if (!g_turnip_gipa) {
        ALOGE("Failed to resolve vkGetInstanceProcAddr from Turnip");
        dlclose(g_turnip_handle);
        g_turnip_handle = nullptr;
        goto cleanup;
    }

    g_turnip_gdpa = (PFN_vkGetDeviceProcAddr)dlsym(g_turnip_handle, "vkGetDeviceProcAddr");
    if (!g_turnip_gdpa) {
        ALOGE("Failed to resolve vkGetDeviceProcAddr from Turnip");
        dlclose(g_turnip_handle);
        g_turnip_handle = nullptr;
        goto cleanup;
    }

    ALOGI("Turnip loaded — installing hooks");

	bytehook_hook_all(NULL, "__system_property_find", (void *)my_system_property_find, NULL, NULL);
    bytehook_hook_all(NULL, "__system_property_get", (void *)my_system_property_get, NULL, NULL);
	
    gipa_stub = (PFN_vkGetInstanceProcAddr)shadowhook_hook_sym_name("libvulkan.so", "vkGetInstanceProcAddr", (void *)hooked_vkGetInstanceProcAddr, nullptr);
    gdpa_stub = (PFN_vkGetDeviceProcAddr)shadowhook_hook_sym_name("libvulkan.so", "vkGetDeviceProcAddr", (void *)hooked_vkGetDeviceProcAddr, nullptr);

#ifdef OVERCLOCK
    ALOGI("Overclock mode: turbo on, priority -20 (ensure active cooling!)");
    adrenotools_set_turbo(true);
    setpriority(PRIO_PROCESS, 0, -20);
#else
    ALOGI("Standard mode: turbo off");
    adrenotools_set_turbo(false);
#endif
    
    ALOGI("Turnip hooks installed successfully");

cleanup:
    env->ReleaseStringUTFChars(jPath, base_cache_path);
    env->DeleteLocalRef(jPath);
    env->DeleteLocalRef(fileClass);
    env->DeleteLocalRef(cacheFileObj);
    env->DeleteLocalRef(contextClass);
    free(native_lib_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
//  JNI entry point
// ─────────────────────────────────────────────────────────────────────────────
void perform_init(JavaVM *vm) {
    ALOGI("JNI_OnLoad: started");

    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
    }

    jclass    activityThreadCls = (jclass)env->NewGlobalRef(
        env->FindClass("android/app/ActivityThread"));
    jmethodID currentAppMid = env->GetStaticMethodID(
        activityThreadCls, "currentApplication", "()Landroid/app/Application;");

    jobject app = env->CallStaticObjectMethod(activityThreadCls, currentAppMid);

    if (app) {
        ALOGI("JNI_OnLoad: Application available immediately, init now");
        init_turnip_driver(env, app);
    } else {
        ALOGI("JNI_OnLoad: Application not ready, deferring init to background thread");
        std::thread([vm]() {
            JNIEnv *t_env = nullptr;
            vm->AttachCurrentThread(&t_env, nullptr);

            jclass    atCls  = t_env->FindClass("android/app/ActivityThread");
            jmethodID caMid  = t_env->GetStaticMethodID(
                atCls, "currentApplication", "()Landroid/app/Application;");

            jobject t_app = nullptr;
            for (int i = 0; i < 20 && !t_app; ++i) {
                t_app = t_env->CallStaticObjectMethod(atCls, caMid);
                if (!t_app)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (t_app) {
                init_turnip_driver(t_env, t_app);
            } else {
                ALOGE("JNI_OnLoad: Application never became available — Turnip not loaded");
            }

            vm->DetachCurrentThread();
        }).detach();
    }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_java_vm = vm;
    std::call_once(g_init_flag, perform_init, vm);
    return JNI_VERSION_1_6;
}
