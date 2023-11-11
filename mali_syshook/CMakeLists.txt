cmake_minimum_required(VERSION 3.18)
project(mali_syshook CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(MALI_SYS_SRCS
    hook.cpp
    log_jsonl.cpp
    kbase_decode.cpp
    shader_dump.cpp
    vk_hook.cpp

    # Headers kept in source-group for IDE discoverability; no
    # codegen.
    mali_base_kernel.h
    mali_base_csf_kernel.h
    mali_kbase_ioctl.h
    mali_kbase_csf_ioctl.h
    log_jsonl.h
    kbase_decode.h
    shader_dump.h
    vk_hook.h
)

source_group(mali FILES ${MALI_SYS_SRCS})

add_library(mali_syshook SHARED ${MALI_SYS_SRCS})

# Vulkan headers come from the NDK sysroot — they exist for API
# level >= 24. We don't link against libvulkan because we shadow
# its exports; the ICD loader resolves through dlsym(RTLD_NEXT).
target_include_directories(mali_syshook PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(mali_syshook PRIVATE
    -Wall -Wno-unused-function -Wno-unused-parameter)

# Hide internal symbols; only the exported (`HOOK_EXPORT`) hooks
# should be visible to LD_PRELOAD lookups.
target_compile_options(mali_syshook PRIVATE -fvisibility=hidden)
target_link_options(mali_syshook PRIVATE
    -Wl,--exclude-libs,ALL
    -Wl,--no-undefined)

target_link_libraries(mali_syshook PRIVATE log dl)
