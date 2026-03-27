cmake_minimum_required(VERSION 3.14)

if(NOT ${CMAKE_ANDROID_ARCH_ABI} STREQUAL arm64-v8a)
	message(FATAL_ERROR "Unsupported target architecture: ${CMAKE_ANDROID_ARCH_ABI}. Please make an issue on the repo!")
endif()

project(adrenotools LANGUAGES CXX C)

set(GEN_INSTALL_TARGET OFF CACHE BOOL "")

add_subdirectory(lib/linkernsbypass)
add_subdirectory(lib/ShadowHook/shadowhook/src/main/cpp shadowhook_build)

set(LIB_SOURCES src/bcenabler.cpp
                src/driver.cpp
                include/adrenotools/bcenabler.h
                include/adrenotools/driver.h
                include/adrenotools/priv.h)

add_library(adrenotools ${LIB_SOURCES})

target_include_directories(adrenotools PUBLIC include)
target_include_directories(adrenotools PRIVATE .)
target_include_directories(adrenotools PRIVATE lib/ShadowHook/shadowhook/src/main/cpp/include)
target_compile_options(adrenotools PRIVATE -Wall -Wextra)
target_link_libraries(adrenotools android -Wl,--whole-archive linkernsbypass -Wl,--no-whole-archive shadowhook log)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(shadowhook PRIVATE -Wno-error=unsafe-buffer-usage -Wno-unsafe-buffer-usage)
endif()

if(TARGET shadowhook)
    target_compile_options(shadowhook PRIVATE 
        -Wno-error=declaration-after-statement
        -Wno-declaration-after-statement
        -Wno-error=unsafe-buffer-usage
        -Wno-unsafe-buffer-usage
		-Wno-error=reserved-identifier
        -Wno-reserved-identifier
		-Wno-unused-macros
        -Wno-error=unused-macros
    )

	target_link_options(shadowhook PRIVATE "-Wl,--undefined-version")
    
    # Force C99 only for ShadowHook's C files
    set_target_properties(shadowhook PROPERTIES 
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
    )
endif()

add_subdirectory(src/hook)

if (${GEN_INSTALL_TARGET})
  configure_file(adrenotools.pc.in adrenotools.pc @ONLY)
  install(FILES ${CMAKE_BINARY_DIR}/adrenotools.pc DESTINATION lib/pkgconfig)
  install(TARGETS adrenotools main_hook file_redirect_hook gsl_alloc_hook hook_impl)
  install(DIRECTORY include/
          DESTINATION include
          FILES_MATCHING PATTERN "*.h*")
endif()
