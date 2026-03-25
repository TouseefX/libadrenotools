// SPDX-License-Identifier: BSD-2-Clause
// Copyright © 2021 Billy Laws

#include <fstream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdio.h>
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

#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, "AdrenoToolsPatch", __VA_ARGS__)
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
        	ALOGE("FAILURE: Memory mapping flag was not specified\n");
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

static void init_turnip_driver() {
    Dl_info info;
    if (!dladdr((void*)init_turnip_driver, &info) || !info.dli_fname) {
        ALOGE("dladdr failed");
        return;
    }
    
    std::string hook_lib_dir = std::string(info.dli_fname).substr(0, std::string(info.dli_fname).find_last_of("/"));
    
    std::string pkg_name;
    std::ifstream cmdline("/proc/self/cmdline");
    if (!(cmdline >> pkg_name)) {
        ALOGE("Failed to read cmdline");
        return;
    }
    // Clean null terminator if present
    pkg_name = pkg_name.c_str(); 
    
    std::string base_data_dir = "/data/data/" + pkg_name;
    std::string cache_dir = base_data_dir + "/cache/turnip/";
    
    mkdir((base_data_dir + "/cache").c_str(), 0777); 
    mkdir(cache_dir.c_str(), 0777);
    chmod(cache_dir.c_str(), 0777);
    
    std::string driver_name = "libvulkan_freedreno.so";
    std::string src_path = hook_lib_dir + "/" + driver_name;
    std::string dst_path = cache_dir + driver_name;
    
    std::ifstream src(src_path, std::ios::binary);
    std::ofstream dst(dst_path, std::ios::binary | std::ios::trunc);
    
    if (src.is_open() && dst.is_open()) {
        dst << src.rdbuf();
        dst.close();
        src.close();
        chmod(dst_path.c_str(), 0755);
        ALOGI("Successfully copied driver to %s", dst_path.c_str());
    } else {
        ALOGE("Copy failed! Src: %s (Open: %d), Dst: %s (Open: %d)", 
              src_path.c_str(), src.is_open(), dst_path.c_str(), dst.is_open());
        return;
    }
    
    std::string ld_library_path = getenv("LD_LIBRARY_PATH") ? getenv("LD_LIBRARY_PATH") : "";
    ld_library_path = cache_dir + ":" + hook_lib_dir + ":" + ld_library_path;
    
    std::string icd_json_path = cache_dir + "libvulkan_freedreno.json";
    std::string icd_json_content = R"({
        "file_format_version": "1.0.0",
        "ICD": {
            "library_path": ")" + cache_dir + driver_name + R"(",
            "api_version": "1.3.0"
        }
    })";

    std::ofstream icd_file(icd_json_path);
    if (icd_file.is_open()) {
        icd_file << icd_json_content;
        icd_file.close();
    }

    setenv("VK_ICD_FILENAMES", icd_json_path.c_str(), 1);
    setenv("LD_LIBRARY_PATH", ld_library_path.c_str(), 1);
    setenv("MESA_LOADER_DRIVER_OVERRIDE", "turnip", 1);
    setenv("DISABLE_VULKAN_SWAPCHAIN_LAYER", "1", 1);
    setenv("ADRENOTOOLS_DRIVER_FILE", dst_path.c_str(), 1);
    
    const char* system_lib_dir = "/system/lib64";
    std::string redirect_dir = base_data_dir + "/cache/redirect/";
    mkdir(redirect_dir.c_str(), 0755);
    
    void* handle = adrenotools_open_libvulkan(
       RTLD_NOW,                 // dlopenMode
       ADRENOTOOLS_DRIVER_CUSTOM, // featureFlags
       cache_dir.c_str(),        // tmpLibDir (CRITICAL: needs a writable path for hooks)
       hook_lib_dir.c_str(),     // hookLibDir
       cache_dir.c_str(),        // customDriverDir (where you copied Turnip)
       driver_name.c_str(),      // customDriverName (libvulkan_freedreno.so)
       redirect_dir.c_str(),                  // fileRedirectDir (not needed usually)
       nullptr                   // userMappingHandle (not needed usually)
    );

    if (handle) {
        ALOGI("✓ Turnip driver loaded for %s", pkg_name.c_str());
    } else {
        ALOGE("✗ adrenotools_open_libvulkan failed for %s", pkg_name.c_str());
    }
}

__attribute__((constructor(50)))
void auto_init_driver() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;
    
    std::thread loader([]() {
        int timeout_ms = 1000; // Stop trying after 1 second
        int elapsed = 0;

        while (!linkernsbypass_load_status()) {
            if (elapsed >= timeout_ms) {
                ALOGE("FAILURE: linkernsbypass timed out after 1s");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            elapsed++;
        }

        // The moment it's ready, run the driver init immediately
        ALOGI("linkernsbypass ready after %dms. Initializing Turnip...", elapsed);
        init_turnip_driver();
    });
    loader.join();
}
