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

#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, "AdrenoToolsPatch", __VA_ARGS__)

static PFN_vkGetInstanceProcAddr gipa_stub = nullptr;
static PFN_vkGetDeviceProcAddr   gdpa_stub = nullptr;

void *adrenotools_open_libvulkan(int dlopenFlags, int featureFlags, const char *tmpLibDir, const char *hookLibDir, const char *customDriverDir, const char *customDriverName, const char *fileRedirectDir, void **userMappingHandle) {
    if (!linkernsbypass_load_status()) {
        ALOGE("FAILURE: Could not load linkernsbypass\n");
        return nullptr;
    }

    if (android_get_device_api_level() >= 29 && !tmpLibDir)
        tmpLibDir = nullptr;

    if (!(featureFlags & ADRENOTOOLS_DRIVER_FILE_REDIRECT) && fileRedirectDir) {
         ALOGE("FAILURE: ADRENOTOOLS_DRIVER_FILE_REDIRECT present but no file redirect folder found\n");
        return nullptr;
    }

    if (!(featureFlags & ADRENOTOOLS_DRIVER_CUSTOM) && (customDriverDir || customDriverName)) {
        ALOGE("FAILURE: ADRENOTOOLS_DRIVER_CUSTOM present but no custom driver name or folder found\n");
        return nullptr;
    }

    if (!(featureFlags & ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT) && userMappingHandle) {
        ALOGE("FAILURE: ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT present but no user mapping handle found\n");
        return nullptr;
    }

    struct stat buf{};

    if (featureFlags & ADRENOTOOLS_DRIVER_CUSTOM) {
        if (!customDriverName || !customDriverDir) {
            ALOGE("FAILURE: ADRENOTOOLS_DRIVER_CUSTOM present but no custom driver name or folder parameter was specified\n");
            return nullptr;
        }

        if (stat((std::string(customDriverDir) + customDriverName).c_str(), &buf) != 0) {
            ALOGE("FAILURE: ADRENOTOOLS_DRIVER_CUSTOM present but importable driver doesn't exist\n");
            return nullptr;
        }
    }

    if (featureFlags & ADRENOTOOLS_DRIVER_FILE_REDIRECT) {
        if (!fileRedirectDir) {
            ALOGE("FAILURE: ADRENOTOOLS_DRIVER_REDIRECT_DIR present but no folder parameter was found\n");
            return nullptr;
        }

        if (stat(fileRedirectDir, &buf) != 0) {
            ALOGE("FAILURE: ADRENOTOOLS_DRIVER_REDIRECT_DIR present but specified redirect folder doesn't exist\n");
            return nullptr;
        }
    }

    auto hookNs{android_create_namespace("adrenotools-libvulkan", hookLibDir, nullptr, ANDROID_NAMESPACE_TYPE_SHARED, nullptr, nullptr)};

    if (!linkernsbypass_link_namespace_to_default_all_libs(hookNs)) {
        return nullptr;
    }

    auto hookImpl{linkernsbypass_namespace_dlopen("libhook_impl.so", RTLD_NOW, hookNs)};
    if (!hookImpl) {
        ALOGE("FAILURE: Couldn't preload the hook implementation\n");
        return nullptr;
    }

    auto initHookParam{reinterpret_cast<void (*)(const void *)>(dlsym(hookImpl, "init_hook_param"))};
    if (!initHookParam) {
        ALOGE("FAILURE: Couldn't init hook params\n");
        return nullptr;
    }

    auto importMapping{[&]() -> adrenotools_gpu_mapping * {
        if (featureFlags & ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT) {
            adrenotools_gpu_mapping *mapping{new adrenotools_gpu_mapping{}};
            *userMappingHandle = mapping;
            return mapping;
        } else {
        	ALOGW("WARN: Memory mapping flag was not specified\n");
            return nullptr;
        }
    }()};

    initHookParam(new HookImplParams(featureFlags, tmpLibDir, hookLibDir, customDriverDir, customDriverName, fileRedirectDir, importMapping));

    if (!linkernsbypass_namespace_dlopen("libmain_hook.so", RTLD_GLOBAL, hookNs)) {
        ALOGE("FAILURE: Failed to load libvulkan into the isolated namespace\n");
        return nullptr;
    }

    return linkernsbypass_namespace_dlopen_unique("/system/lib64/libvulkan.so", tmpLibDir, dlopenFlags, hookNs);
}

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
    if (ret)
        goto err;

    info.id = userMemImport.id;
    ret = ioctl(kgslFd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    if (ret)
        goto err;

    importMapping->host_ptr = hostPtr;
    importMapping->gpu_addr = info.gpuaddr;
    importMapping->size = size;
    importMapping->flags = 0xc2600;

    close(kgslFd);
    return true;

err:
    close(kgslFd);
    return false;
}

bool adrenotools_mem_gpu_allocate(void *handle, uint64_t *size) {
    auto mapping{reinterpret_cast<adrenotools_gpu_mapping *>(handle)};

    kgsl_gpuobj_alloc gpuobjAlloc{};
    gpuobjAlloc.size  = *size;
    gpuobjAlloc.flags = KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT
                      | KGSL_MEMFLAGS_IOCOHERENT;

    kgsl_gpuobj_info info{};

    int kgslFd{open("/dev/kgsl-3d0", O_RDWR)};
    if (kgslFd < 0)
        return false;

    int ret{ioctl(kgslFd, IOCTL_KGSL_GPUOBJ_ALLOC, &gpuobjAlloc)};
    if (ret)
        goto err;

    *size = gpuobjAlloc.mmapsize;

    info.id = gpuobjAlloc.id;

    ret = ioctl(kgslFd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    if (ret)
        goto err;

    mapping->host_ptr = nullptr;
    mapping->gpu_addr = info.gpuaddr;
    mapping->size = *size;
    mapping->flags = 0xc2600;

    close(kgslFd);
    return true;

err:
    close(kgslFd);
    return false;
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
        .type = KGSL_PROP_PWRCTRL,
        .value = reinterpret_cast<void *>(&enable),
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

    int result = setenv(varName, value, 1);
    if (result != 0) {
        ALOGE("FAILURE adrenotools_set_freedreno_env: Failed to set '%s' (errno: %d)", varName, errno);
        return false;
    }

    const char *verifyValue = std::getenv(varName);
    if (verifyValue && std::strcmp(verifyValue, value) == 0) {
        return true;
    } else {
        ALOGW("WARN adrenotools_set_freedreno_env: Verification failed for '%s'", varName);
        return false;
    }
}

static std::mutex g_init_mutex;
static void *g_turnip_handle = NULL;
static PFN_vkGetInstanceProcAddr g_turnip_gipa = NULL;
static PFN_vkGetDeviceProcAddr g_turnip_gdpa = nullptr;
static std::once_flag g_init_flag;
static JavaVM* g_java_vm = nullptr;

static PFN_vkVoidFunction hooked_vkGetInstanceProcAddr(VkInstance instance, const char* pName) {
    if (g_turnip_gipa) {
        auto func = g_turnip_gipa(instance, pName);
        if (func) return func;
    }
    return gipa_stub(instance, pName);
}

static PFN_vkVoidFunction hooked_vkGetDeviceProcAddr(VkDevice device, const char* pName) {
    if (g_turnip_gdpa) {
        auto func = g_turnip_gdpa(device, pName);
        if (func) return func;
    }
    if (gdpa_stub)
        return gdpa_stub(device, pName);
    return nullptr;
}

static char* get_native_library_dir(JNIEnv* env, jobject context) {
    char* native_libdir = nullptr;

    if (context != nullptr) {
        jclass contextClass = env->FindClass("android/content/Context");
        jmethodID getAppInfo = env->GetMethodID(contextClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
        jobject appInfo = env->CallObjectMethod(context, getAppInfo);

        jclass appInfoClass = env->GetObjectClass(appInfo);
        jfieldID fieldId = env->GetFieldID(appInfoClass, "nativeLibraryDir", "Ljava/lang/String;");
        jstring jPath = (jstring)env->GetObjectField(appInfo, fieldId);

        if (jPath) {
            const char* path_chars = env->GetStringUTFChars(jPath, nullptr);
            if (path_chars) {
                native_libdir = strdup(path_chars);
                env->ReleaseStringUTFChars(jPath, path_chars);
            }
        }

        env->DeleteLocalRef(contextClass);
        env->DeleteLocalRef(appInfo);
        env->DeleteLocalRef(appInfoClass);
    }

    return native_libdir;
}

void applyTurnipOptimizations() {
    void* libvulkan = dlopen("libvulkan.so", RTLD_NOW);
    if (!libvulkan) return;
	
    auto pfnCreateInstance = (PFN_vkCreateInstance)dlsym(libvulkan, "vkCreateInstance");
    auto pfnEnumeratePhysicalDevices = (PFN_vkEnumeratePhysicalDevices)dlsym(libvulkan, "vkEnumeratePhysicalDevices");
    auto pfnGetPhysicalDeviceProperties = (PFN_vkGetPhysicalDeviceProperties)dlsym(libvulkan, "vkGetPhysicalDeviceProperties");
    auto pfnDestroyInstance = (PFN_vkDestroyInstance)dlsym(libvulkan, "vkDestroyInstance");

    if (!pfnCreateInstance || !pfnEnumeratePhysicalDevices) {
        dlclose(libvulkan);
        return;
    }
	
    VkInstance tempInstance;
    VkInstanceCreateInfo createInfo = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    if (pfnCreateInstance(&createInfo, nullptr, &tempInstance) == VK_SUCCESS) {
        uint32_t count = 0;
        pfnEnumeratePhysicalDevices(tempInstance, &count, nullptr);
        if (count > 0) {
            std::vector<VkPhysicalDevice> devices(count);
            pfnEnumeratePhysicalDevices(tempInstance, &count, devices.data());

            VkPhysicalDeviceProperties props;
            pfnGetPhysicalDeviceProperties(devices[0], &props);
            
            std::string name(props.deviceName);
            if (name.find("Adreno (TM) 7") != std::string::npos || 
                name.find("Adreno (TM) 8") != std::string::npos) {
				
				#ifdef OVERCLOCK
				    ALOGI("Use Gmem");
				    setenv("TU_DEBUG", "gmem,noconfirm,noflushall,lowprecision", 1);
				#else
				    ALOGI("Use Sysmem");
				    setenv("TU_DEBUG", "sysmem,noconfirm,noflushall,lowprecision", 1);
				#endif
            } else {
                setenv("TU_DEBUG", "sysmem,noconfirm,noflushall,lowprecision,nolrz", 1);
                ALOGI("Use System Memory");
            }
        }
        pfnDestroyInstance(tempInstance, nullptr);
    }
    dlclose(libvulkan);
}

static void init_turnip_driver(JNIEnv* env, jobject context) {
    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_turnip_handle != nullptr) {
        ALOGI("init_turnip_driver: already initialized, skipping");
        return;
    }

    char* native_lib_dir = get_native_library_dir(env, context);

    char fixed_dir[512];
    snprintf(fixed_dir, sizeof(fixed_dir), "%s/", native_lib_dir);
    __android_log_print(ANDROID_LOG_ERROR, "AdrenoToolsPatch", "Native Lib Dir: %s", fixed_dir);
    
    setenv("MESA_LIBGL_DRIVERS_PATH", fixed_dir, 1);
    
    
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getCacheDir = env->GetMethodID(contextClass, "getCacheDir", "()Ljava/io/File;");
    jobject cacheFileObj = env->CallObjectMethod(context, getCacheDir);
    jclass fileClass = env->GetObjectClass(cacheFileObj);
    jmethodID getAbsolutePath = env->GetMethodID(fileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jstring jPath = (jstring)env->CallObjectMethod(cacheFileObj, getAbsolutePath);

    const char* base_cache_path = env->GetStringUTFChars(jPath, nullptr);

    char tmpdir[512];
    snprintf(tmpdir, sizeof(tmpdir), "%s/turnip_tmp/", base_cache_path);
    mkdir(tmpdir, 0775);

    char cache_dir[512];
    snprintf(cache_dir, sizeof(cache_dir), "%s/turnip_shader_cache/", base_cache_path);
    mkdir(cache_dir, 0775);

    setenv("MESA_DISK_CACHE_DIR", cache_dir, 1);

    g_turnip_handle = adrenotools_open_libvulkan(
        RTLD_GLOBAL | RTLD_NOW,
        ADRENOTOOLS_DRIVER_CUSTOM,
        tmpdir,
        native_lib_dir,
        fixed_dir,
        "libvulkan_freedreno.so",
        NULL,
        NULL
    );

    if (!g_turnip_handle) {
        ALOGE("Failed to load Turnip via adrenotools");
        goto cleanup;
    }

    g_turnip_gipa = (PFN_vkGetInstanceProcAddr)dlsym(g_turnip_handle, "vkGetInstanceProcAddr");
    if (!g_turnip_gipa) {
        ALOGE("Failed to get vkGetInstanceProcAddr from Turnip");
        goto cleanup;
    }

    g_turnip_gdpa = (PFN_vkGetDeviceProcAddr)dlsym(g_turnip_handle, "vkGetDeviceProcAddr");
    if (!g_turnip_gdpa) {
        ALOGE("Failed to get vkGetDeviceProcAddr from Turnip");
        goto cleanup;
    }

    ALOGI("Turnip loaded, setting up hooks...");

    gipa_stub = (PFN_vkGetInstanceProcAddr)shadowhook_hook_sym_name("libvulkan.so", "vkGetInstanceProcAddr", (void*)hooked_vkGetInstanceProcAddr, NULL);
    gdpa_stub = (PFN_vkGetDeviceProcAddr)shadowhook_hook_sym_name("libvulkan.so", "vkGetDeviceProcAddr", (void*)hooked_vkGetDeviceProcAddr, NULL);
	
	#ifdef OVERCLOCK
	    ALOGI("Enabling Overclock make sure you have a fan cooler");
	    adrenotools_set_turbo(true);
	    setpriority(PRIO_PROCESS, 0, -20);
	#else
	    ALOGI("using stranded mode");
	    adrenotools_set_turbo(false);
	#endif

    ALOGI("Turnip hooks installed successfully");

cleanup:
    env->ReleaseStringUTFChars(jPath, base_cache_path);
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(cacheFileObj);
    env->DeleteLocalRef(fileClass);
    free(native_lib_dir);
}

__attribute__((constructor))
static void global_atomic_init() {
    setenv("MESA_VULKAN_ICD_SELECT", "turnip", 1);
    setenv("MESA_VK_IGNORE_CONFORMANCE_WARNING", "true", 1);
    setenv("MESA_VK_DEVICE_SELECT_FORCE_DEFAULT_DEVICE", "1", 1);
	setenv("MESA_GLSL_CACHE_DISABLE", "false", 1);
    setenv("MESA_GLSL_CACHE_MAX_SIZE", "512M", 1);
	setenv("MESA_VK_CACHE_CONTROL", "1", 1);
    setenv("FD_DEV_FEATURES", "enable_tp_ubwc_flag_hint=1", 1);
    
    setenv("GALLIUM_PRINT_OPTIONS", "0", 1);
    setenv("MESA_DEBUG", "silent", 1);
	setenv("MESA_NO_ERROR", "1", 1);

	#ifdef OVERCLOCK
	    setenv("KGSL_CONTEXT_PRIORITY", "1", 1);
	    setenv("mesa_glthread", "true", 1);
	    setenv("ADRENO_TURBO", "1", 1);
	    setenv("vblank_mode", "0", 1);
	    setenv("MESA_VK_WSI_PRESENT_MODE", "mailbox", 1); // don't use immediate if you want to edit this code take the risk gpu controls the system
	#else
	    setenv("KGSL_CONTEXT_PRIORITY", "2", 1);
	    setenv("mesa_glthread", "false", 1); // creates more heat then expected because system uses opengl
	    setenv("ADRENO_TURBO", "0", 1);
	    setenv("vblank_mode", "1", 1);
	    setenv("MESA_VK_WSI_PRESENT_MODE", "fifo", 1); // Use fifo for stablely
        setenv("TU_ROBUST_BUFFER_ACCESS", "0", 1);
	#endif
    
    setenv("UNITY_DISABLE_GRAPHICS_DRIVER_CHECK", "1", 1);
    setenv("UNITY_VULKAN_ENABLE_VALIDATION_LAYERS", "0", 1);
	setenv("UNITY_GFX_DEVICE_API", "vulkan", 1);

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

	char sdk_str[8] = {};
    __system_property_get("ro.build.version.sdk", sdk_str);
    int sdk = atoi(sdk_str);

    ALOGI("Android SDK: %d", sdk);

    unsetenv("MESA_VK_VERSION_OVERRIDE");

	char oneui_str[PROP_VALUE_MAX] = {0};
    bool is_affected_oneui = false;
    
    if (__system_property_get("ro.build.version.oneui", oneui_str) > 0) {
        int raw_version = atoi(oneui_str);
		
        if (raw_version >= 60000) {
            is_affected_oneui = true;
            int major = raw_version / 10000;
            int minor = (raw_version % 10000) / 100;
            ALOGI("Targeted One UI version detected: %d.%d", major, minor);
        }
	}

	if (is_affected_oneui && sdk >= 30) {
        setenv("FD_DEV_FEATURES", "enable_tp_ubwc_flag_hint=1", 1);
        ALOGI("One UI 6.0+: UBWC flag hint enabled to prevent texture glitches");
    }

	applyTurnipOptimizations();

    shadowhook_init(SHADOWHOOK_MODE_SHARED, true);
}

void perform_init(JavaVM* vm) {
	ALOGI("JNI_OnLoad: started");
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
    }

    static jclass activityThreadCls = (jclass)env->NewGlobalRef(env->FindClass("android/app/ActivityThread"));
    static jmethodID currentAppMid = env->GetStaticMethodID(activityThreadCls, "currentApplication", "()Landroid/app/Application;");

    jobject app = env->CallStaticObjectMethod(activityThreadCls, currentAppMid);

    if (app) {
        ALOGI("JNI_OnLoad: Initializing Turnip immediately");
        init_turnip_driver(env, app);
    } else {
        std::thread([vm]() {
            JNIEnv* t_env = nullptr;
            vm->AttachCurrentThread(&t_env, nullptr);

            jclass atCls = t_env->FindClass("android/app/ActivityThread");
            jmethodID caMid = t_env->GetStaticMethodID(atCls, "currentApplication", "()Landroid/app/Application;");

            jobject t_app = nullptr;
            for (int i = 0; i < 10 && !t_app; ++i) {
                t_app = t_env->CallStaticObjectMethod(atCls, caMid);
                if (!t_app) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (t_app) init_turnip_driver(t_env, t_app);
            vm->DetachCurrentThread();
        }).detach();
    }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_java_vm = vm;
    std::call_once(g_init_flag, perform_init, vm);
    return JNI_VERSION_1_6;
}
