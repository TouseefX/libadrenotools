#include "hook_impl.h"
#include <sys/system_properties.h>

__attribute__((visibility("default"))) void *android_dlopen_ext(const char *filename, int flags, const android_dlextinfo *extinfo) {
    return hook_android_dlopen_ext(filename, flags, extinfo);
}

__attribute__((visibility("default"))) void *android_load_sphal_library(const char *filename, int flags) {
    return hook_android_load_sphal_library(filename, flags);
}

__attribute__((visibility("default"))) int __system_property_get(const char *name, char *value) {
    return hook___system_property_get(name, value);
}

__attribute__((visibility("default"))) void __system_property_read_callback(const prop_info *pi, void (*callback)(void *, const char *, const char *, uint32_t), void *cookie) {
    hook___system_property_read_callback(pi, callback, cookie);
}
