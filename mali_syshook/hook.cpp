#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <string.h>
#include "mali_base_kernel.h"
#include "mali_kbase_ioctl.h"
#include "mali_base_csf_kernel.h"
#include "mali_kbase_csf_ioctl.h"

typedef void* (*mmap_func)(void *, size_t, int, int, int, loff_t);
typedef int (*open_func)(const char *, int flags, ...);
typedef int (*PFN_open2)(const char *, int flags);
typedef int (*PFN_ioctl)(int fd,  unsigned long request, void*);

static int mali_fd = 0;

#define API_EXT extern "C" __attribute__((visibility("default")))

open_func origin_open = NULL;
open_func origin_open64 = NULL;
PFN_open2 origin_open2 = NULL;
PFN_ioctl origin_ioctl = NULL;

API_EXT void __attribute__((constructor(101))) constructor_util(void) {
    origin_open = (open_func)dlsym(RTLD_NEXT, "open64");
    origin_open64 = (open_func)dlsym(RTLD_NEXT, "open64");
    origin_ioctl = (PFN_ioctl)dlsym(RTLD_NEXT, "ioctl");
    origin_open2 = (PFN_open2)dlsym(RTLD_NEXT, "__open_2");
//    dlsym(handle, "mmap");
//    dlsym(handle, "mmap64");
//    dlsym(handle, "ioctl");
}

API_EXT int test_zack() { return 0; }

API_EXT int
open(const char *path, int flags, ...)
{
    va_list args;
    va_start(args, flags);
    if (origin_open == nullptr)
    {
        origin_open = (open_func)dlsym(RTLD_NEXT, "open");
    }
    int o = origin_open(path, flags, args);
    va_end(args);
    return o;
}

API_EXT int
__open_2(const char *path, int flags)
{
    if (origin_open2 == nullptr)
    {
        origin_open2 = (PFN_open2)dlsym(RTLD_NEXT, "__open_2");
    }
    int o = origin_open2(path, flags);
    if (!strcmp("/dev/mali0", path))
    {
        mali_fd = o;
    }
    return o;
}

API_EXT int
open64(const char *path, int flags, ...)
{
    //PROLOG(open64);
    va_list args;
    va_start(args, flags);
    int o = origin_open64(path, flags, args);
    va_end(args);
    return o;
}

#define IOCTL_CASE(request) (_IOWR(_IOC_TYPE(request), _IOC_NR(request), \
				   _IOC_SIZE(request)))

API_EXT int ioctl(int fd,  unsigned long request, ...) {
    if (origin_ioctl == nullptr)
    {
        origin_ioctl = (PFN_ioctl)dlsym(RTLD_NEXT, "ioctl");
    }
    va_list args;
    va_start(args, request);
    void *p = va_arg(args, void *);
    va_end(args);
    int r = origin_ioctl(fd, request, p);
    if (fd == mali_fd)
    {
        if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_GET_GPUPROPS))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_ALLOC))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_QUERY))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_FREE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_GET_DDK_VERSION))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_JIT_INIT_10_2))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_JIT_INIT_11_5))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_JIT_INIT))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_SYNC))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_COMMIT))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_ALIAS))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_IMPORT))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_EXEC_INIT))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_FLAGS_CHANGE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_FIND_CPU_OFFSET))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_MEM_PROFILE_ADD))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_STICKY_RESOURCE_MAP))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_STICKY_RESOURCE_UNMAP))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_GET_CONTEXT_ID))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_TLSTREAM_ACQUIRE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_TLSTREAM_FLUSH))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_STREAM_CREATE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_FENCE_VALIDATE))
        {
            fd++;
        }
        /* Queue */
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_REGISTER))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_KICK))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_BIND))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_REGISTER_EX))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_TERMINATE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_EVENT_SIGNAL))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_KCPU_QUEUE_CREATE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_KCPU_QUEUE_DELETE))
        {
            fd++;
        }
        // vkQueuePresent
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_KCPU_QUEUE_ENQUEUE))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_TILER_HEAP_INIT))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_TILER_HEAP_TERM))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_GET_GLB_IFACE))
        {
            fd++;
        }
        // step 0
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_VERSION_CHECK))
        {
            fd++;
        }
        // step 1
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_SET_FLAGS))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CONTEXT_PRIORITY_CHECK))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_SET_LIMITED_CORE_COUNT))
        {
            fd++;
        }
        else if (IOCTL_CASE(request) == IOCTL_CASE(KBASE_IOCTL_CS_CPU_QUEUE_DUMP))
        {
            fd++;
        }
        else
        {
            fd = _IOC_NR(request);
            int type = _IOC_TYPE(request);
            int size = _IOC_SIZE(request);
            fd++;
        }

    }
    return r;
}