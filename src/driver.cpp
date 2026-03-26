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

#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, "AdrenoToolsPatch", __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, "AdrenoToolsPatch", __VA_ARGS__)

void *adrenotools_open_libvulkan(int dlopenFlags, int featureFlags, const char *tmpLibDir, const char *hookLibDir, const char *customDriverDir, const char *customDriverName, const char *fileRedirectDir, void **userMappingHandle) {
    // Bail out if linkernsbypass failed to load, this probably means we're on api < 28
    if (!linkernsbypass_load_status()) {
        ALOGE("FAILURE: Could not load linkernsbypass\n");
        return nullptr;
    }

    // Always use memfd on Q+ since it's guaranteed to work only if tmplib is not set
    if (android_get_device_api_level() >= 29 && !tmpLibDir)
        tmpLibDir = nullptr;

    // Verify that params for specific features are only passed if they are enabled
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

    // Verify that params for enabled features are correct
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

    // Verify that params for enabled features are correct
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

    // Create a namespace that can isolate our hook from the classloader namespace
    auto hookNs{android_create_namespace("adrenotools-libvulkan", hookLibDir, nullptr, ANDROID_NAMESPACE_TYPE_SHARED, nullptr, nullptr)};

    // Link it to the default namespace so the hook can use libandroid etc
    if (!linkernsbypass_link_namespace_to_default_all_libs(hookNs)) {
        return nullptr;
    }

    // Preload the hook implementation, otherwise we get a weird issue where despite being in NEEDED of the hook lib the hook's symbols will overwrite ours and cause an infinite loop
    auto hookImpl{linkernsbypass_namespace_dlopen("libhook_impl.so", RTLD_NOW, hookNs)};
    if (!hookImpl) {
        ALOGE("FAILURE: Couldn't preload the hook implementation\n");
        return nullptr;
    }

    // Pass parameters to the hook implementation
    auto initHookParam{reinterpret_cast<void (*)(const void *)>(dlsym(hookImpl, "init_hook_param"))};
    if (!initHookParam) {
        ALOGE("FAILURE: Couldn't init hook params\n");
        return nullptr;
    }


    auto importMapping{[&]() -> adrenotools_gpu_mapping * {
        if (featureFlags & ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT) {
            // This will be leaked, but it's not a big deal since it's only a few bytes
            adrenotools_gpu_mapping *mapping{new adrenotools_gpu_mapping{}};
            *userMappingHandle = mapping;
            return mapping;
        } else {
        	ALOGW("WARN: Memory mapping flag was not specified\n");
            return nullptr;
        }
    }()};

    initHookParam(new HookImplParams(featureFlags, tmpLibDir, hookLibDir, customDriverDir, customDriverName, fileRedirectDir, importMapping));

    // Load the libvulkan hook into the isolated namespace
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
    importMapping->flags = 0xc2600; //!< Unknown flags, but they are required for the mapping to work

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
    mapping->flags = 0xc2600; //!< Unknown flags, but they are required for the mapping to work

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
    close (kgslFd);
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

static void* g_vulkan_handle = nullptr;
static JavaVM* g_java_vm = nullptr;

// Get native library directory via Context API (like GameNativePerformance)
static char* get_native_library_dir(JNIEnv* env, jobject context) {
    char* native_libdir = nullptr;

    if (context != nullptr) {
        jclass class_ = env->FindClass("android/content/ContextWrapper");
        if (!class_) return nullptr;

        jmethodID getFilesDir = env->GetMethodID(class_, "getFilesDir", "()Ljava/io/File;");
        if (!getFilesDir) return nullptr;

        jobject filesDirObj = env->CallObjectMethod(context, getFilesDir);
        jclass fileClass = env->GetObjectClass(filesDirObj);
        jmethodID getAbsolutePath = env->GetMethodID(fileClass, "getAbsolutePath", "()Ljava/lang/String;");

        jstring absolutePath = (jstring)env->CallObjectMethod(filesDirObj, getAbsolutePath);
        if (absolutePath) {
            const char* path_chars = env->GetStringUTFChars(absolutePath, nullptr);
            if (path_chars) {
                native_libdir = strdup(path_chars);
                env->ReleaseStringUTFChars(absolutePath, path_chars);
            }
        }

        env->DeleteLocalRef(class_);
        env->DeleteLocalRef(filesDirObj);
        env->DeleteLocalRef(fileClass);
    }

    return native_libdir;
}

// Get driver path from app's files directory
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

static void init_turnip_driver(JNIEnv* env, jobject context) {
    ALOGI("Initializing Turnip Driver...");

    char* driver_path = nullptr;
    char* native_lib_dir = nullptr;
    char* tmpdir = nullptr;

    // Get paths via Context API (more reliable than /data/data/)
    driver_path = get_driver_path(env, context);
    if (!driver_path || access(driver_path, F_OK) != 0) {
        ALOGE("Driver path not found or inaccessible: %s", driver_path ? driver_path : "NULL");
        goto cleanup;
    }

    native_lib_dir = get_native_library_dir(env, context);
    if (!native_lib_dir) {
        ALOGE("Failed to get native library directory");
        goto cleanup;
    }

    // Create temp directory for adrenotools hooks (CRITICAL)
    char tmpdir_buffer[512];
    snprintf(tmpdir_buffer, sizeof(tmpdir_buffer), "%stemp/", driver_path);
    mkdir(tmpdir_buffer, S_IRWXU | S_IRWXG);
    chmod(tmpdir_buffer, 0777);
    tmpdir = tmpdir_buffer;

    ALOGI("Driver path: %s", driver_path);
    ALOGI("Native lib dir: %s", native_lib_dir);
    ALOGI("Temp dir: %s", tmpdir);

    // Key: Don't manually set VK_ICD_FILENAMES or VK_DRIVER_FILES
    // Let adrenotools handle this internally!
    // Only set these if adrenotools doesn't set them properly:
    setenv("MESA_LOADER_DRIVER_OVERRIDE", "turnip", 1);
    setenv("TU_DEBUG", "sysmem", 1);

    // Open libvulkan with custom driver
    g_vulkan_handle = adrenotools_open_libvulkan(
        RTLD_LOCAL | RTLD_NOW,              // dlopenMode
        ADRENOTOOLS_DRIVER_CUSTOM,          // featureFlags
        tmpdir,                             // tmpLibDir (CRITICAL for hooks)
        native_lib_dir,                     // hookLibDir
        driver_path,                        // customDriverDir
        "libvulkan_freedreno.so",           // customDriverName
        nullptr,                            // fileRedirectDir
        nullptr                             // userMappingHandle
    );

    if (g_vulkan_handle) {
        ALOGI("✓ Turnip driver successfully loaded!");
    } else {
        ALOGE("✗ Failed to load Turnip driver via adrenotools");
    }

cleanup:
    if (driver_path) free(driver_path);
    if (native_lib_dir) free(native_lib_dir);
}

extern "C" JNIEXPORT void JNICALL
Java_com_game_TurnipLoader_initTurnipDriver(JNIEnv* env, jclass clazz, jobject context) {
    if (!context) {
        ALOGE("Context is null!");
        return;
    }
    init_turnip_driver(env, context);
}

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    ALOGI("JNI_OnLoad called");
    g_java_vm = vm;
    return JNI_VERSION_1_6;
}
