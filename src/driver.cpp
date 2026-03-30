// SPDX-License-Identifier: BSD-2-Clause
// Copyright © 2021 Billy Laws

// List TODO:
// fix performance
// make more apps supported (only supports games not apps like adia64)
// more stability
// more support
// add more freedeno support (turniup with opengl es)

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

#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, "AdrenoToolsPatch", __VA_ARGS__)

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

    kgsl_gpuobj_import userMemImport{
        .priv = reinterpret_cast<uint64_t>(&addr),
        .priv_len = size,
        .flags = KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT | KGSL_MEMFLAGS_IOCOHERENT,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };

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

    kgsl_gpuobj_alloc gpuobjAlloc{
        .size = *size,
        .flags = KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT | KGSL_MEMFLAGS_IOCOHERENT,
    };

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
static JavaVM* g_java_vm = nullptr;
static void *gipa_stub = nullptr;
static void* gdpa_stub = nullptr;

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

static char* get_driver_path(JNIEnv* env, jobject context) {
    char* driver_path = nullptr;

    if (context != nullptr) {
        jclass class_ = env->FindClass("android/content/ContextWrapper");
        if (!class_) return nullptr;

        jmethodID getFilesDir = env->GetMethodID(class_, "getFilesDir", "()Ljava/io/File;");
        jobject filesDirObj = env->CallObjectMethod(context, getFilesDir);
        jclass fileClass = env->GetObjectClass(filesDirObj);
        jmethodID getAbsolutePath = env->GetMethodID(fileClass, "getAbsolutePath", "()Ljava/lang/String;");

        jstring absolutePath = (jstring)env->CallObjectMethod(filesDirObj, getAbsolutePath);
        if (absolutePath) {
            const char* path_chars = env->GetStringUTFChars(absolutePath, nullptr);
            if (path_chars) {
                if (asprintf(&driver_path, "%s/turnip/", path_chars) == -1)
                    driver_path = nullptr;
                env->ReleaseStringUTFChars(absolutePath, path_chars);
            }
        }

        env->DeleteLocalRef(class_);
    }

    return driver_path;
}

static PFN_vkVoidFunction hooked_vkGetInstanceProcAddr(VkInstance instance, const char* pName) {
    if (g_turnip_gipa) {
        auto func = g_turnip_gipa(instance, pName);
        if (func) return func;
    }
    
    typedef PFN_vkVoidFunction (*orig_t)(VkInstance, const char*);
    return ((orig_t)gipa_stub)(instance, pName);
}

static PFN_vkVoidFunction hooked_vkGetDeviceProcAddr(VkDevice device, const char* pName) {
    if (g_turnip_gipa) {
        auto func = g_turnip_gipa((VkInstance)device, pName);
        if (func) return func;
    }
    
    if (gdpa_stub) {
        typedef PFN_vkVoidFunction (*gdpa_t)(VkDevice, const char*);
        return ((gdpa_t)gdpa_stub)(device, pName);
    }
    return nullptr;
}

static void init_turnip_driver(JNIEnv* env, jobject context) {
    std::lock_guard<std::mutex> lock(g_init_mutex);
    void* temp_stub = nullptr;
    if (g_turnip_handle != nullptr) {
        ALOGI("init_turnip_driver: already initialized, skipping");
        return;
    }
    
    char* driver_path = get_driver_path(env, context);
    char* native_lib_dir = get_native_library_dir(env, context);

    if (!driver_path || access(driver_path, F_OK) != 0) {
        ALOGE("Driver path not found");
        return;
    }

    char tmpdir[512];
    snprintf(tmpdir, sizeof(tmpdir), "%s/temp/", driver_path);
    mkdir(tmpdir, S_IRWXU | S_IRWXG);

    char cache_dir[512];
    snprintf(cache_dir, sizeof(cache_dir), "%sshader_cache/", driver_path);
    mkdir(cache_dir, S_IRWXU | S_IRWXG);

    setenv("MESA_DISK_CACHE_DIR", cache_dir, 1);

    g_turnip_handle = adrenotools_open_libvulkan(
        RTLD_LOCAL | RTLD_NOW,
        ADRENOTOOLS_DRIVER_CUSTOM,
        tmpdir,
        native_lib_dir,
        driver_path,
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

    ALOGI("Turnip loaded, setting up hooks...");

    gipa_stub = shadowhook_hook_sym_name("libvulkan.so", "vkGetInstanceProcAddr", (void*)hooked_vkGetInstanceProcAddr, NULL);
    gdpa_stub = shadowhook_hook_sym_name("libvulkan.so", "vkGetDeviceProcAddr", (void*)hooked_vkGetDeviceProcAddr, NULL);

    if (gipa_stub) {
        ALOGI("ShadowHook: Turnip hooks installed successfully");
    } else {
        ALOGE("ShadowHook: Failed to install one or more hooks");
    }

cleanup:
    free(driver_path);
    free(native_lib_dir);
}

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    ALOGI("JNI_OnLoad called");
    g_java_vm = vm;

    setenv("MESA_VK_VERSION_OVERRIDE", "1.3", 1);
    setenv("MESA_VULKAN_ICD_SELECT", "turnip", 1);
    setenv("FD_DEV_FEATURES", "enable_tp_ubwc_flag_hint=1", 1);
    setenv("MESA_VK_TRACE", "false", 1);
    setenv("MESA_DEBUG", "silent", 1);
    setenv("GALLIUM_PRINT_OPTIONS", "0", 1);
    setenv("MESA_VK_IGNORE_CONFORMANCE_WARNING", "true", 1);
    setenv("TU_DEBUG", "noconfirm,noflushall", 1);
    setenv("TU_DEVELOPER_MODE", "1", 1);
    setenv("MESA_VK_DEVICE_SELECT_FORCE_DEFAULT_DEVICE", "1", 1);
    
    setenv("MESA_LOADER_DRIVER_OVERRIDE", "kgsl", 1);
    setenv("GALLIUM_DRIVER", "kgsl", 1);
    setenv("EGL_PLATFORM", "android", 1);
    setenv("MESA_GL_VERSION_OVERRIDE", "4.6", 1);
    setenv("MESA_GLES_VERSION_OVERRIDE", "3.2", 1);

    shadowhook_init(SHADOWHOOK_MODE_SHARED, true);

    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && env) {
        jclass activityThread = env->FindClass("android/app/ActivityThread");
        jmethodID currentApp = env->GetStaticMethodID(activityThread,
            "currentApplication", "()Landroid/app/Application;");
        jobject app = env->CallStaticObjectMethod(activityThread, currentApp);

        if (app) {
            ALOGI("JNI_OnLoad: got application context, self-initializing Turnip");
            init_turnip_driver(env, app);
        } else {
            ALOGW("JNI_OnLoad: currentApplication is null, retrying on background thread");
            std::thread([]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

                JavaVM* vm = g_java_vm;
                if (!vm) return;

                JNIEnv* env = nullptr;
                vm->AttachCurrentThread(&env, nullptr);

                jclass activityThread = env->FindClass("android/app/ActivityThread");
                jmethodID currentApp = env->GetStaticMethodID(activityThread,
                    "currentApplication", "()Landroid/app/Application;");
                jobject app = env->CallStaticObjectMethod(activityThread, currentApp);

                if (app) {
                    ALOGI("Deferred init: got application context, initializing Turnip");
                    init_turnip_driver(env, app);
                } else {
                    ALOGE("Deferred init: currentApplication still null, giving up");
                }

                vm->DetachCurrentThread();
            }).detach();
        }
    } else {
        ALOGE("JNI_OnLoad: failed to get JNIEnv");
    }

    return JNI_VERSION_1_6;
}