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
#include <unordered_map>
#include <cstdlib>
#include <algorithm>

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
static std::unordered_map<std::string, std::string>* g_mesa_props = nullptr;
static std::mutex g_props_mutex;
static int (*orig_system_property_get)(const char*, char*) = nullptr;

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

// HELPERS
static void set_tu_debug_flag(const char* flag, bool enable = true) {
	auto& props = *g_mesa_props;
	
    std::string key = std::string("vendor.mesa.tu.debug.") + flag;
    props[key] = enable ? "1" : "0";
}

static void clear_tu_debug_flags() {
	auto& props = *g_mesa_props;
	
    for (const char* flag : {
        "gmem", "sysmem", "noconfirm", "noflushall",
        "lowprecision", "nolrz", "noubwc"
    }) {
        std::string key = std::string("vendor.mesa.tu.debug.") + flag;
        props[key] = "0";
    }
}

static void init_map_if_needed() {
    if (g_mesa_props == nullptr) {
        g_mesa_props = new std::unordered_map<std::string, std::string>();
    }
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

static int hooked_system_property_get(const char* name, char* value) {
    if (name) {
        std::lock_guard<std::mutex> lock(g_props_mutex);
        if (g_mesa_props) { // If null, we just skip to the original call
            auto it = g_mesa_props->find(name);
            if (it != g_mesa_props->end()) {
                strlcpy(value, it->second.c_str(), 92); // 92 = PROP_VALUE_MAX
                return static_cast<int>(it->second.size());
            }
        }
    }
    return orig_system_property_get(name, value);
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
	auto& props = *g_mesa_props;
    void* libvulkan = dlopen("libvulkan.so", RTLD_NOW);
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

    VkInstance tempInstance = VK_NULL_HANDLE;
    VkInstanceCreateInfo ci = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};

    if (pfnCreateInstance(&ci, nullptr, &tempInstance) != VK_SUCCESS) {
        dlclose(libvulkan);
        return;
    }

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
        
        clear_tu_debug_flags();

        switch (gen) {
            case AdrenoGen::A8xx:
                // A8xx: large GMEM, force gmem path
                props["vendor.mesa.tu.gmem"]     = "1";
                set_tu_debug_flag("gmem");
                set_tu_debug_flag("noconfirm");
                set_tu_debug_flag("noflushall");
                set_tu_debug_flag("lowprecision");
                props["vendor.mesa.fd.dev.features"] = "enable_tp_ubwc_flag_hint=1";
                ALOGI("A8xx: gmem + UBWC hint");
                break;

            case AdrenoGen::A7xx:
#ifdef OVERCLOCK
                // A7xx OC: gmem benefits from extra clock headroom
                props["vendor.mesa.tu.gmem"] = "1";
                set_tu_debug_flag("gmem");
                ALOGI("A7xx OC: gmem rendering");
#else
                // A7xx stock: sysmem runs cooler
                props["vendor.mesa.tu.gmem"] = "0";
                set_tu_debug_flag("sysmem");
                ALOGI("A7xx stock: sysmem rendering");
#endif
                set_tu_debug_flag("noconfirm");
                set_tu_debug_flag("noflushall");
                set_tu_debug_flag("lowprecision");
                props["vendor.mesa.fd.dev.features"] = "enable_tp_ubwc_flag_hint=1";
                ALOGI("A7xx: UBWC hint enabled");
                break;

            case AdrenoGen::A6xx:
                // A6xx: sysmem, UBWC safe without hint
                props["vendor.mesa.tu.gmem"] = "0";
                set_tu_debug_flag("sysmem");
                set_tu_debug_flag("noconfirm");
                set_tu_debug_flag("noflushall");
                set_tu_debug_flag("lowprecision");
                ALOGI("A6xx: sysmem, no UBWC override needed");
                break;

            case AdrenoGen::A5xx:
                // A5xx: no UBWC, no reliable LRZ
                props["vendor.mesa.tu.gmem"]         = "0";
                props["vendor.mesa.fd.dev.features"] = "";
                set_tu_debug_flag("sysmem");
                set_tu_debug_flag("noconfirm");
                set_tu_debug_flag("nolrz");
                set_tu_debug_flag("noubwc");
                ALOGW("A5xx: conservative sysmem, UBWC+LRZ disabled");
                break;

            default:
                props["vendor.mesa.tu.gmem"] = "0";
                set_tu_debug_flag("sysmem");
                set_tu_debug_flag("noconfirm");
                set_tu_debug_flag("noflushall");
                set_tu_debug_flag("lowprecision");
                set_tu_debug_flag("nolrz");
                ALOGW("Unknown Adreno: safe fallback");
                break;
        }
    }

    pfnDestroyInstance(tempInstance, nullptr);
    dlclose(libvulkan);
}

static void apply_sdk_tunables() {
    std::lock_guard<std::mutex> lock(g_props_mutex);
    init_map_if_needed();
    auto& props = *g_mesa_props;
    
    char sdk_str[8] = {};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);
    ALOGI("Android SDK: %d", sdk);
    
    if (sdk >= 34) {
        ALOGI("Android 14+: no Vulkan version override");
    } else if (sdk >= 32) {
        props["vendor.mesa.vk.version.override"] = "1.3";
        ALOGI("Android 12L/13: Vulkan 1.3");
    } else if (sdk >= 31) {
        props["vendor.mesa.vk.version.override"] = "1.2";
        ALOGI("Android 12: Vulkan 1.2");
    } else {
        props["vendor.mesa.vk.version.override"] = "1.1";
        ALOGI("Android <12: Vulkan 1.1");
    }
    
    char oneui_str[PROP_VALUE_MAX] = {};
    if (__system_property_get("ro.build.version.oneui", oneui_str) > 0) {
        int raw = atoi(oneui_str);
        if (raw >= 60000 && sdk >= 30) {
            if (props.find("vendor.mesa.fd.dev.features") == props.end()) {
                props["vendor.mesa.fd.dev.features"] = "enable_tp_ubwc_flag_hint=1";
                ALOGI("One UI 6.0+: UBWC hint set");
            }
        }
    }
    
    props["vendor.mesa.glsl.cache.disable"]  = "false";
    props["vendor.mesa.glsl.cache.max.size"] = "512M";
    props["vendor.mesa.vk.cache.control"]    = "1";
    
#ifdef OVERCLOCK
    ALOGI("OC mode: no heap cap");
#else
    long pages     = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    long heap_mb   = (long)std::max(256LL,
                         (long long)pages * page_size / (1024 * 1024) / 2);
    props["vendor.mesa.tu.override.heap.size"] = std::to_string(heap_mb);
    ALOGI("Heap: %ld MB", heap_mb);
#endif

    props["vendor.mesa.vulkan.icd.select"]                     = "turnip";
    props["vendor.mesa.vk.ignore.conformance.warning"]         = "true";
    props["vendor.mesa.vk.device.select.force.default.device"] = "1";
    props["vendor.mesa.gralloc.api"]                           = "gralloc4";
    props["vendor.mesa.extension.override"]                    = "-VK_KHR_external_memory_fd";
    props["vendor.mesa.gallium.print.options"]                 = "0";
    props["vendor.mesa.debug"]                                 = "silent";
    props["vendor.mesa.no.error"]                              = "1";
    props["vendor.mesa.tu.robust.buffer.access"]               = "0";

#ifdef OVERCLOCK
    props["vendor.mesa.glthread"]            = "true";
    props["vendor.mesa.vk.wsi.present.mode"] = "mailbox";
#else
    props["vendor.mesa.glthread"]            = "false";
    props["vendor.mesa.vk.wsi.present.mode"] = "fifo";
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────
__attribute__((constructor))
static void global_atomic_init() {
    apply_sdk_tunables();
    applyTurnipOptimizations();
    
#ifdef OVERCLOCK
    setenv("KGSL_CONTEXT_PRIORITY", "1", 1);
    setenv("ADRENO_TURBO",          "1", 1);
    setenv("vblank_mode",           "0", 1);
#else
    setenv("KGSL_CONTEXT_PRIORITY", "2", 1);
    setenv("ADRENO_TURBO",          "0", 1);
    setenv("vblank_mode",           "1", 1);
#endif

    setenv("UNITY_DISABLE_GRAPHICS_DRIVER_CHECK",   "1",      1);
    setenv("UNITY_VULKAN_ENABLE_VALIDATION_LAYERS",  "0",      1);
    setenv("UNITY_GFX_DEVICE_API",                  "vulkan", 1);
    
    shadowhook_init(SHADOWHOOK_MODE_SHARED, true);
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
    
    shadowhook_hook_sym_name("libc.so", "__system_property_get", reinterpret_cast<void*>(hooked_system_property_get), reinterpret_cast<void**>(&orig_system_property_get));
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
