cmake_minimum_required(VERSION 3.14...4.3)

if(NOT ${CMAKE_ANDROID_ARCH_ABI} STREQUAL arm64-v8a)
	message(FATAL_ERROR "Unsupported target architecture: ${CMAKE_ANDROID_ARCH_ABI}. Please make an issue on the repo!")
endif()

project(adrenotools LANGUAGES CXX C)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--undefined-version")

set(GEN_INSTALL_TARGET OFF CACHE BOOL "")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(lib/linkernsbypass)

macro(add_library name type)
  if("${type}" STREQUAL "SHARED")
    _add_library(${name} STATIC ${ARGN})
  else()
    _add_library(${name} ${type} ${ARGN})
  endif()
endmacro()

add_subdirectory(lib/ShadowHook/shadowhook/src/main/cpp shadowhook_build)

set_target_properties(shadowhook PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(TARGET shadowhook AND NOT TARGET shadowhook::shadowhook)
    add_library(shadowhook::shadowhook ALIAS shadowhook)
endif()

file(WRITE "${CMAKE_BINARY_DIR}/shadowhookConfig.cmake" "include_guard()")
file(WRITE "${CMAKE_BINARY_DIR}/shadowhookConfigVersion.cmake" "set(PACKAGE_VERSION 1.0.0)\nset(PACKAGE_ACCEPTABLE TRUE)")

set(shadowhook_DIR "${CMAKE_BINARY_DIR}" CACHE PATH "Path to shadowhook config" FORCE)

include(FetchContent)
FetchContent_Declare(
  bytehook
  GIT_REPOSITORY https://github.com/bytedance/bhook
  GIT_TAG        main
  SOURCE_SUBDIR  bytehook/src/main/cpp
)
FetchContent_MakeAvailable(bytehook)

set(LIB_SOURCES src/bcenabler.cpp
                src/driver.cpp
                include/adrenotools/bcenabler.h
                include/adrenotools/driver.h
                include/adrenotools/priv.h)

add_library(adrenotools SHARED ${LIB_SOURCES})

target_include_directories(adrenotools PUBLIC include)
target_include_directories(adrenotools PRIVATE .)
target_include_directories(adrenotools PRIVATE 
    lib/ShadowHook/shadowhook/src/main/cpp/include
    ${bytehook_SOURCE_DIR}/bytehook/src/main/cpp/include
)
target_compile_options(adrenotools PRIVATE -Wall -Wextra)
target_link_libraries(adrenotools 
    android 
    vulkan
    -Wl,--whole-archive 
        linkernsbypass 
        shadowhook 
        bytehook
        main_hook
        hook_impl
        file_redirect_hook
        gsl_alloc_hook
    -Wl,--no-whole-archive
)

set_target_properties(adrenotools PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(shadowhook PRIVATE -Wno-error=unsafe-buffer-usage -Wno-unsafe-buffer-usage)
    target_compile_options(adrenotools PRIVATE 
        -Wno-error 
        -Wno-c++98-compat 
        -Wno-c++98-compat-pedantic
        -Wno-sign-conversion
        -Wno-gnu-anonymous-struct
        -Wno-nested-anon-types
    )
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
    
    # Force C99 only for ShadowHook's C files
    set_target_properties(shadowhook PROPERTIES 
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
    )
endif()

if(TARGET bytehook)
    set_target_properties(bytehook PROPERTIES INTERFACE_COMPILE_OPTIONS "")
    
    # Re-apply only what ByteHook needs internally
    target_include_directories(bytehook PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/ShadowHook/shadowhook/src/main/cpp/include
    )
    
    target_compile_options(bytehook PRIVATE 
        -Wno-everything 
        -Wno-error 
        -Wno-declaration-after-statement
        -Wno-unsafe-buffer-usage
        -Wno-pre-c11-compat
    )
    
    set_target_properties(bytehook PROPERTIES 
        C_STANDARD 11
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
