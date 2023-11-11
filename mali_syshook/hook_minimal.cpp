// Smoke-test build, iterative: enable wrappers one at a time.
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#define TAG "MALI_SYSHOOK"
#define EXPORT extern "C" __attribute__((visibility("default")))

extern "C" __attribute__((constructor(101))) void minimal_ctor() {
   __android_log_print(ANDROID_LOG_INFO, TAG,
                       "minimal ctor pid=%d", getpid());
}

#ifdef HOOK_OPEN
typedef int (*PFN_open)(const char *, int, ...);
static PFN_open real_open = nullptr;
EXPORT int open(const char *path, int flags, ...) {
   if (!real_open) real_open = (PFN_open)dlsym(RTLD_NEXT, "open");
   mode_t mode = 0;
   if (flags & O_CREAT) {
      va_list ap;
      va_start(ap, flags);
      mode = va_arg(ap, int);
      va_end(ap);
   }
   int fd = real_open ? real_open(path, flags, mode) : -1;
   __android_log_print(ANDROID_LOG_INFO, TAG, "open '%s' = %d", path, fd);
   return fd;
}
#endif

#ifdef HOOK_OPEN_2
typedef int (*PFN_open_2)(const char *, int);
static PFN_open_2 real_open_2 = nullptr;
EXPORT int __open_2(const char *path, int flags) {
   if (!real_open_2) real_open_2 = (PFN_open_2)dlsym(RTLD_NEXT, "__open_2");
   int fd = real_open_2 ? real_open_2(path, flags) : -1;
   __android_log_print(ANDROID_LOG_INFO, TAG, "__open_2 '%s' = %d", path, fd);
   return fd;
}
#endif

#ifdef HOOK_MMAP64
typedef void *(*PFN_mmap64)(void *, size_t, int, int, int, off64_t);
static PFN_mmap64 real_mmap64 = nullptr;
EXPORT void *mmap64(void *a, size_t l, int p, int f, int fd, off64_t off) {
   if (!real_mmap64) real_mmap64 = (PFN_mmap64)dlsym(RTLD_NEXT, "mmap64");
   void *r = real_mmap64 ? real_mmap64(a, l, p, f, fd, off) : MAP_FAILED;
   return r;
}
#endif

#ifdef HOOK_MMAP
typedef void *(*PFN_mmap)(void *, size_t, int, int, int, off_t);
static PFN_mmap real_mmap = nullptr;
EXPORT void *mmap(void *a, size_t l, int p, int f, int fd, off_t off) {
   if (!real_mmap) real_mmap = (PFN_mmap)dlsym(RTLD_NEXT, "mmap");
   void *r = real_mmap ? real_mmap(a, l, p, f, fd, off) : MAP_FAILED;
   return r;
}
#endif
