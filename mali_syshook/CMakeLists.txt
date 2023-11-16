set(MALI_SYS_SRCS
	mali_base_csf_kernel.h
	mali_base_kernel.h
	mali_kbase_csf_ioctl.h
	hook.cpp
)

source_group(mali FILES ${MALI_SYS_SRCS})

add_library(mali_syshook SHARED ${MALI_SYS_SRCS})
target_link_libraries(mali_syshook log)