// mali_syshook entrypoint.
//
// LD_PRELOAD wrappers for libc functions used by the Vulkan ICD when
// talking to /dev/mali*. We track the set of mali fds opened by the
// process and instrument ioctl/mmap/munmap/close for those fds only.
// Other fds pass through unchanged.
//
// Build:  see CMakeLists.txt / build_android.bat (NDK arm64).
// Deploy: `LD_PRELOAD=/data/local/tmp/libmali_syshook.so ./victim`
// Output: JSONL events to $MALI_HOOK_LOG (default
//         /data/local/tmp/mali_hook.jsonl) and/or logcat if
//         $MALI_HOOK_LOGCAT=1.

#include "kbase_decode.h"
#include "log_jsonl.h"
#ifndef PACKED
#define PACKED __attribute__((packed))
#endif
#include "mali_base_csf_kernel.h"
#include "mali_base_kernel.h"
#include "mali_kbase_csf_ioctl.h"
#include "mali_kbase_ioctl.h"
#include "shader_dump.h"
#include "vk_hook.h"

#include <android/log.h>
#include <atomic>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mutex>
#include <set>
#include <string>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define TAG "MALI_SYSHOOK"
#define HOOK_EXPORT extern "C" __attribute__((visibility("default")))

namespace {

using PFN_open = int (*)(const char *, int, ...);
using PFN_open64 = int (*)(const char *, int, ...);
using PFN_open_2 = int (*)(const char *, int);
using PFN_openat = int (*)(int, const char *, int, ...);
using PFN_openat_2 = int (*)(int, const char *, int);
using PFN_close = int (*)(int);
using PFN_dup = int (*)(int);
using PFN_dup2 = int (*)(int, int);
using PFN_dup3 = int (*)(int, int, int);
using PFN_fcntl = int (*)(int, int, ...);
using PFN_ioctl = int (*)(int, int, void *);
using PFN_mmap = void *(*)(void *, size_t, int, int, int, off_t);
using PFN_mmap64 = void *(*)(void *, size_t, int, int, int, off64_t);
using PFN_munmap = int (*)(void *, size_t);

std::atomic<PFN_open> real_open{nullptr};
std::atomic<PFN_open64> real_open64{nullptr};
std::atomic<PFN_open_2> real_open_2{nullptr};
std::atomic<PFN_openat> real_openat{nullptr};
std::atomic<PFN_openat_2> real_openat_2{nullptr};
std::atomic<PFN_close> real_close{nullptr};
std::atomic<PFN_dup> real_dup{nullptr};
std::atomic<PFN_dup2> real_dup2{nullptr};
std::atomic<PFN_dup3> real_dup3{nullptr};
std::atomic<PFN_fcntl> real_fcntl{nullptr};
std::atomic<PFN_ioctl> real_ioctl{nullptr};
std::atomic<PFN_mmap> real_mmap{nullptr};
std::atomic<PFN_mmap64> real_mmap64{nullptr};
std::atomic<PFN_munmap> real_munmap{nullptr};

template <typename Fn>
Fn resolve(std::atomic<Fn> &slot, const char *name) {
   Fn v = slot.load(std::memory_order_acquire);
   if (v) {
      return v;
   }
   v = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, name));
   slot.store(v, std::memory_order_release);
   return v;
}

std::mutex g_mali_fds_mutex;
std::set<int> g_mali_fds;

std::atomic<uint64_t> g_blob_seq{0};

struct MmapRegion {
   int fd;
   void *addr;
   size_t length;
   uint64_t offset;
   int prot;
};

std::mutex g_mmap_regions_mutex;
std::vector<MmapRegion> g_mmap_regions;

bool is_mali_fd(int fd) {
   std::lock_guard<std::mutex> g(g_mali_fds_mutex);
   return g_mali_fds.find(fd) != g_mali_fds.end();
}

void register_mali_fd(int fd) {
   std::lock_guard<std::mutex> g(g_mali_fds_mutex);
   g_mali_fds.insert(fd);
}

void unregister_mali_fd(int fd) {
   std::lock_guard<std::mutex> g(g_mali_fds_mutex);
   g_mali_fds.erase(fd);
}

void replace_fd_tracking(int oldfd, int newfd) {
   std::lock_guard<std::mutex> g(g_mali_fds_mutex);
   bool old_mali = g_mali_fds.find(oldfd) != g_mali_fds.end();
   if (old_mali) {
      g_mali_fds.insert(newfd);
   } else {
      g_mali_fds.erase(newfd);
   }
}

bool path_is_mali(const char *path) {
   if (!path) {
      return false;
   }
   // /dev/mali0, /dev/mali1, ... or just /dev/mali
   if (strncmp(path, "/dev/mali", 9) != 0) {
      return false;
   }
   char rest = path[9];
   return rest == '\0' || (rest >= '0' && rest <= '9');
}

void note_open(const char *path, int flags, int fd, void *caller) {
   bool mali = path_is_mali(path);
   // Only log mali fd opens (the rest is noise — bionic does ~40
   // opens per process at startup). caller is the LR captured at
   // the LD_PRELOAD wrapper, useful for IDA cross-reference.
   if (!mali) {
      return;
   }
   if (fd >= 0) {
      register_mali_fd(fd);
   }
   mali_hook::LogBuilder ev("open");
   ev.str("path", path ? path : "");
   ev.hex("flags", (uint64_t)(uint32_t)flags);
   ev.hex("caller", (uint64_t)(uintptr_t)caller);
   ev.i64("fd", fd);
   ev.boolean("mali", true);
   if (fd < 0) {
      ev.i64("errno", errno);
   }
}

void note_fd_copy(const char *op, int oldfd, int newfd, int flags,
                  void *caller) {
   if (!is_mali_fd(newfd)) {
      return;
   }
   mali_hook::LogBuilder ev("fd_copy");
   ev.str("op", op);
   ev.i64("oldfd", oldfd);
   ev.i64("newfd", newfd);
   ev.hex("caller", (uint64_t)(uintptr_t)caller);
   if (flags) {
      ev.hex("flags", (uint64_t)(uint32_t)flags);
   }
}

bool open_needs_mode(int flags) {
#ifdef O_TMPFILE
   return (flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
#else
   return (flags & O_CREAT) != 0;
#endif
}

const char *blob_dir() {
   static char dir[512];
   static bool init = false;
   if (!init) {
      const char *env = getenv("MALI_HOOK_BLOB_DIR");
      if (env && env[0]) {
         snprintf(dir, sizeof(dir), "%s", env);
      } else {
         const char *log = getenv("MALI_HOOK_LOG");
         if (log && log[0]) {
            snprintf(dir, sizeof(dir), "%s.blobs", log);
         } else {
            snprintf(dir, sizeof(dir), "/data/local/tmp/mali_hook.blobs");
         }
      }
      mkdir(dir, 0777);
      init = true;
   }
   return dir;
}

bool replay_snapshot_enabled() {
   const char *env = getenv("MALI_HOOK_REPLAY_SNAPSHOT");
   return env && env[0] && strcmp(env, "0") != 0;
}

size_t replay_snapshot_max_bytes() {
   const char *env = getenv("MALI_HOOK_REPLAY_SNAPSHOT_MAX_BYTES");
   if (!env || !env[0]) {
      return 4 * 1024 * 1024;
   }
   long v = strtol(env, nullptr, 0);
   return v > 0 ? (size_t)v : 4 * 1024 * 1024;
}

// mincore() probe: a resident page returns vec bit0 set. Absent pages
// of a sparse GPU pool (EXEC shaders at 0x8000_xxxx, the 16 MB command
// pools) would SIGSEGV/EFAULT on access, so we skip them.
static bool page_is_resident(const void *addr) {
   unsigned char vec = 0;
   void *base = (void *)((uintptr_t)addr & ~(uintptr_t)0xFFF);
   if (mincore(base, 0x1000, &vec) != 0)
      return false;
   return (vec & 1) != 0;
}

bool dump_blob_file(const char *prefix, const void *data, size_t size,
                    char *out_path, size_t out_path_size) {
   if (!data && size) {
      return false;
   }
   uint64_t seq = g_blob_seq.fetch_add(1, std::memory_order_relaxed);
   snprintf(out_path, out_path_size, "%s/%s_%06llu.bin", blob_dir(), prefix,
            (unsigned long long)seq);
   FILE *f = fopen(out_path, "wb");
   if (!f) {
      return false;
   }
   // Page-resilient dump: reserve a large VA but only commit some pages.
   // A straight fwrite() faults the moment it touches an uncommitted
   // page and aborts the whole region. Probe each page with mincore()
   // and substitute a zero page for absent ones, so the output length
   // always equals `size` and file offset == region offset (a GPU VA
   // maps straight to a file offset).
   static const unsigned char zero_page[0x1000] = {0};
   bool ok = true;
   size_t remaining = size;
   const unsigned char *p = (const unsigned char *)data;
   while (remaining) {
      size_t page_off = (uintptr_t)p & 0xFFF;
      size_t chunk = 0x1000 - page_off;
      if (chunk > remaining)
         chunk = remaining;
      const unsigned char *src =
         page_is_resident(p) ? p : (zero_page + page_off);
      if (fwrite(src, 1, chunk, f) != chunk) {
         ok = false;
         break;
      }
      p += chunk;
      remaining -= chunk;
   }
   fclose(f);
   return ok;
}

void note_ioctl_raw_blob(int fd, unsigned long request, const void *arg,
                         const char *phase) {
   size_t size = _IOC_SIZE(request);
   if ((!arg && size) || size > (1u << 20)) {
      return;
   }
   char path[768];
   if (!dump_blob_file(phase, arg, size, path, sizeof(path))) {
      return;
   }
   mali_hook::LogBuilder ev("ioctl_raw");
   ev.str("phase", phase)
       .i64("fd", fd)
       .hex("cmd", (uint64_t)request)
       .str("name", mali_hook::kbase_ioctl_name(request)
                        ? mali_hook::kbase_ioctl_name(request)
                        : "UNKNOWN")
       .u64("size", (uint64_t)size)
       .str("rawPath", path);
}

bool note_user_ptr_blob(int fd, unsigned long request, const char *name,
                        const char *role, const void *ptr, uint64_t count,
                        uint64_t elem_size, int command_index = -1) {
   if (!ptr || !count || !elem_size) {
      return false;
   }
   uint64_t bytes64 = count * elem_size;
   if (elem_size != 0 && bytes64 / elem_size != count) {
      return false;
   }
   if (bytes64 > (1u << 20)) {
      return false;
   }
   char path[768];
   if (!dump_blob_file("userptr", ptr, (size_t)bytes64, path, sizeof(path))) {
      return false;
   }
   mali_hook::LogBuilder ev("user_ptr_blob");
   ev.i64("fd", fd)
       .hex("cmd", (uint64_t)request)
       .str("name", name)
       .str("role", role)
       .hex("userAddr", (uint64_t)(uintptr_t)ptr)
       .u64("count", count)
       .u64("elemSize", elem_size)
       .u64("bytes", bytes64)
       .str("blobPath", path);
   if (command_index >= 0) {
      ev.u64("commandIndex", (uint64_t)command_index);
   }
   return true;
}

void note_kcpu_command_payloads(int fd, unsigned long request,
                                const base_kcpu_command *commands,
                                uint32_t nr_commands) {
   for (uint32_t i = 0; i < nr_commands; i++) {
      const base_kcpu_command &cmd = commands[i];
      int index = (int)i;
      switch (cmd.type) {
      case BASE_KCPU_COMMAND_TYPE_FENCE_SIGNAL:
      case BASE_KCPU_COMMAND_TYPE_FENCE_WAIT:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_fence",
                            (const void *)(uintptr_t)cmd.info.fence.fence,
                            1, sizeof(base_fence), index);
         break;
      case BASE_KCPU_COMMAND_TYPE_CQS_WAIT:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_cqs_wait",
                            (const void *)(uintptr_t)cmd.info.cqs_wait.objs,
                            cmd.info.cqs_wait.nr_objs,
                            sizeof(base_cqs_wait_info), index);
         break;
      case BASE_KCPU_COMMAND_TYPE_CQS_SET:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_cqs_set",
                            (const void *)(uintptr_t)cmd.info.cqs_set.objs,
                            cmd.info.cqs_set.nr_objs,
                            sizeof(base_cqs_set), index);
         break;
      case BASE_KCPU_COMMAND_TYPE_CQS_WAIT_OPERATION:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_cqs_wait_operation",
                            (const void *)(uintptr_t)cmd.info.cqs_wait_operation.objs,
                            cmd.info.cqs_wait_operation.nr_objs,
                            sizeof(base_cqs_wait_operation_info), index);
         break;
      case BASE_KCPU_COMMAND_TYPE_CQS_SET_OPERATION:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_cqs_set_operation",
                            (const void *)(uintptr_t)cmd.info.cqs_set_operation.objs,
                            cmd.info.cqs_set_operation.nr_objs,
                            sizeof(base_cqs_set_operation_info), index);
         break;
      case BASE_KCPU_COMMAND_TYPE_JIT_ALLOC:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_jit_alloc",
                            (const void *)(uintptr_t)cmd.info.jit_alloc.info,
                            cmd.info.jit_alloc.count,
                            sizeof(base_jit_alloc_info), index);
         break;
      case BASE_KCPU_COMMAND_TYPE_JIT_FREE:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_jit_free",
                            (const void *)(uintptr_t)cmd.info.jit_free.ids,
                            cmd.info.jit_free.count, sizeof(uint8_t), index);
         break;
      case BASE_KCPU_COMMAND_TYPE_GROUP_SUSPEND:
         note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                            "kcpu_suspend_buffer",
                            (const void *)(uintptr_t)cmd.info.suspend_buf_copy.buffer,
                            cmd.info.suspend_buf_copy.size, sizeof(uint8_t), index);
         break;
      default:
         break;
      }
   }
}

void note_ioctl_user_ptr_blobs(int fd, unsigned long request, const void *arg) {
   if (!arg) {
      return;
   }
#ifdef KBASE_IOCTL_STICKY_RESOURCE_MAP
   if (request == (unsigned long)KBASE_IOCTL_STICKY_RESOURCE_MAP) {
      const auto *p = (const kbase_ioctl_sticky_resource_map *)arg;
      note_user_ptr_blob(fd, request, "KBASE_IOCTL_STICKY_RESOURCE_MAP",
                         "sticky_resources",
                         (const void *)(uintptr_t)p->address, p->count,
                         sizeof(uint64_t));
      return;
   }
#endif
#ifdef KBASE_IOCTL_STICKY_RESOURCE_UNMAP
   if (request == (unsigned long)KBASE_IOCTL_STICKY_RESOURCE_UNMAP) {
      const auto *p = (const kbase_ioctl_sticky_resource_unmap *)arg;
      note_user_ptr_blob(fd, request, "KBASE_IOCTL_STICKY_RESOURCE_UNMAP",
                         "sticky_resources",
                         (const void *)(uintptr_t)p->address, p->count,
                         sizeof(uint64_t));
      return;
   }
#endif
#ifdef KBASE_IOCTL_KCPU_QUEUE_ENQUEUE
   if (request == (unsigned long)KBASE_IOCTL_KCPU_QUEUE_ENQUEUE) {
      const auto *p = (const kbase_ioctl_kcpu_queue_enqueue *)arg;
      const auto *commands = (const base_kcpu_command *)(uintptr_t)p->addr;
      if (note_user_ptr_blob(fd, request, "KBASE_IOCTL_KCPU_QUEUE_ENQUEUE",
                             "kcpu_commands", commands, p->nr_commands,
                             sizeof(base_kcpu_command))) {
         note_kcpu_command_payloads(fd, request, commands, p->nr_commands);
      }
      return;
   }
#endif
}

void note_mem_import_ref(int fd, unsigned long request, const void *arg) {
   if (request != (unsigned long)KBASE_IOCTL_MEM_IMPORT || !arg) {
      return;
   }
   const auto *p = (const kbase_ioctl_mem_import *)arg;
   if (p->in.type != 2 || !p->in.phandle) {
      return;
   }
   int import_fd = -1;
   memcpy(&import_fd, (const void *)(uintptr_t)p->in.phandle, sizeof(import_fd));
   mali_hook::LogBuilder ev("mem_import_ref");
   ev.i64("fd", fd)
       .hex("cmd", (uint64_t)request)
       .str("name", "KBASE_IOCTL_MEM_IMPORT")
       .hex("flags", p->in.flags)
       .hex("phandle", p->in.phandle)
       .u64("type", p->in.type)
       .u64("padding", p->in.padding)
       .i64("importFd", import_fd);
   if (import_fd >= 0) {
      char link_path[64];
      char target[512];
      snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", import_fd);
      ssize_t n = readlink(link_path, target, sizeof(target) - 1);
      if (n >= 0) {
         target[n] = '\0';
         ev.str("importPath", target);
      }
   }
}

void note_mmap_region(int fd, void *addr, size_t length, uint64_t offset,
                      int prot) {
   std::lock_guard<std::mutex> g(g_mmap_regions_mutex);
   g_mmap_regions.push_back(MmapRegion{fd, addr, length, offset, prot});
}

void forget_mmap_region(void *addr, size_t length) {
   uintptr_t a = (uintptr_t)addr;
   uintptr_t b = a + length;
   std::lock_guard<std::mutex> g(g_mmap_regions_mutex);
   for (auto it = g_mmap_regions.begin(); it != g_mmap_regions.end();) {
      uintptr_t ra = (uintptr_t)it->addr;
      uintptr_t rb = ra + it->length;
      if (a < rb && b > ra) {
         it = g_mmap_regions.erase(it);
      } else {
         ++it;
      }
   }
}

void dump_mmap_snapshots(const char *reason) {
   if (!replay_snapshot_enabled()) {
      return;
   }
   size_t max_bytes = replay_snapshot_max_bytes();
   std::vector<MmapRegion> regions;
   {
      std::lock_guard<std::mutex> g(g_mmap_regions_mutex);
      regions = g_mmap_regions;
   }
   for (const auto &r : regions) {
      if (!(r.prot & PROT_READ) || !r.addr || !r.length) {
         continue;
      }
      size_t bytes = r.length < max_bytes ? r.length : max_bytes;
      char path[768];
      if (!dump_blob_file("mmap", r.addr, bytes, path, sizeof(path))) {
         continue;
      }
      mali_hook::LogBuilder ev("mmap_snapshot");
      ev.str("reason", reason)
          .i64("fd", r.fd)
          .hex("addr", (uint64_t)(uintptr_t)r.addr)
          .u64("length", (uint64_t)r.length)
          .u64("bytes", (uint64_t)bytes)
          .hex("offset", r.offset)
          .hex("prot", (uint64_t)(uint32_t)r.prot)
          .str("snapshotPath", path);
   }
}

bool fcntl_has_no_arg(int cmd) {
   switch (cmd) {
   case F_GETFD:
   case F_GETFL:
#ifdef F_GETOWN
   case F_GETOWN:
#endif
      return true;
   default:
      return false;
   }
}

int call_open_common(const char *path, int flags, mode_t mode, bool has_mode,
                     void *caller) {
   auto fn = resolve(real_open, "open");
   int fd = fn ? (has_mode ? fn(path, flags, mode) : fn(path, flags)) : -1;
   int saved_errno = errno;
   note_open(path, flags, fd, caller);
   errno = saved_errno;
   return fd;
}

int call_open64_common(const char *path, int flags, mode_t mode, bool has_mode,
                       void *caller) {
   auto fn = resolve(real_open64, "open64");
   int fd = fn ? (has_mode ? fn(path, flags, mode) : fn(path, flags)) : -1;
   int saved_errno = errno;
   note_open(path, flags, fd, caller);
   errno = saved_errno;
   return fd;
}

int call_openat_common(int dirfd, const char *path, int flags, mode_t mode,
                       bool has_mode, void *caller) {
   auto fn = resolve(real_openat, "openat");
   int fd = fn ? (has_mode ? fn(dirfd, path, flags, mode)
                           : fn(dirfd, path, flags)) : -1;
   int saved_errno = errno;
   note_open(path, flags, fd, caller);
   errno = saved_errno;
   return fd;
}

struct PendingAlloc {
   bool valid = false;
   uint64_t va_pages = 0;
   uint64_t commit_pages = 0;
   uint64_t flags = 0;
};

PendingAlloc read_pending_alloc(unsigned long request, const void *arg) {
   PendingAlloc pending;
   if (!arg) {
      return pending;
   }
   if (request == (unsigned long)KBASE_IOCTL_MEM_ALLOC) {
      const auto *p = (const kbase_ioctl_mem_alloc *)arg;
      pending.valid = true;
      pending.va_pages = p->in.va_pages;
      pending.commit_pages = p->in.commit_pages;
      pending.flags = p->in.flags;
   }
#ifdef KBASE_IOCTL_MEM_ALLOC_EX
   if (request == (unsigned long)KBASE_IOCTL_MEM_ALLOC_EX) {
      const auto *p = (const kbase_ioctl_mem_alloc_ex *)arg;
      pending.valid = true;
      pending.va_pages = p->in.va_pages;
      pending.commit_pages = p->in.commit_pages;
      pending.flags = p->in.flags;
   }
#endif
   return pending;
}

void note_ioctl_side_effects(int fd, unsigned long request, const void *arg,
                             const PendingAlloc &pending, int ret) {
   if (ret != 0 || !arg) {
      return;
   }
   if (request == (unsigned long)KBASE_IOCTL_MEM_ALLOC) {
      const auto *p = (const kbase_ioctl_mem_alloc *)arg;
      uint64_t pages = pending.commit_pages ? pending.commit_pages
                                            : pending.va_pages;
      mali_hook::shader_dump_note_alloc(fd, p->out.gpu_va, p->out.flags,
                                        pages * 4096);
      return;
   }
#ifdef KBASE_IOCTL_MEM_ALLOC_EX
   if (request == (unsigned long)KBASE_IOCTL_MEM_ALLOC_EX) {
      const auto *p = (const kbase_ioctl_mem_alloc_ex *)arg;
      uint64_t pages = pending.commit_pages ? pending.commit_pages
                                            : pending.va_pages;
      mali_hook::shader_dump_note_alloc(fd, p->out.gpu_va, p->out.flags,
                                        pages * 4096);
      return;
   }
#endif
   if (request == (unsigned long)KBASE_IOCTL_MEM_FLAGS_CHANGE) {
      const auto *p = (const kbase_ioctl_mem_flags_change *)arg;
      mali_hook::shader_dump_note_flags_change(p->gpu_va, p->flags, p->mask);
      return;
   }
   if (request == (unsigned long)KBASE_IOCTL_MEM_FREE) {
      const auto *p = (const kbase_ioctl_mem_free *)arg;
      mali_hook::shader_dump_note_free(p->gpu_addr);
      return;
   }
   if (request == (unsigned long)KBASE_IOCTL_MEM_SYNC) {
      mali_hook::shader_dump_dump_all("mem_sync");
      return;
   }
#ifdef KBASE_IOCTL_CS_QUEUE_KICK
   if (request == (unsigned long)KBASE_IOCTL_CS_QUEUE_KICK) {
      mali_hook::shader_dump_dump_all("cs_queue_kick");
      return;
   }
#endif
#ifdef KBASE_IOCTL_KCPU_QUEUE_ENQUEUE
   if (request == (unsigned long)KBASE_IOCTL_KCPU_QUEUE_ENQUEUE) {
      mali_hook::shader_dump_dump_all("kcpu_queue_enqueue");
      return;
   }
#endif
}

} // namespace

HOOK_EXPORT void __attribute__((constructor(101))) mali_hook_ctor() {
   mali_hook::log_init();
   mali_hook::vk_hook_init();
   __android_log_print(ANDROID_LOG_INFO, TAG,
                       "mali_syshook loaded (pid=%d)", getpid());
}

// ---------------------------------------------------------------------------
// open family
// ---------------------------------------------------------------------------

HOOK_EXPORT int open(const char *path, int flags, ...) {
   mode_t mode = 0;
   bool has_mode = open_needs_mode(flags);
   if (has_mode) {
      va_list ap;
      va_start(ap, flags);
      mode = va_arg(ap, int);
      va_end(ap);
   }
   return call_open_common(path, flags, mode, has_mode,
                           __builtin_return_address(0));
}

HOOK_EXPORT int open64(const char *path, int flags, ...) {
   mode_t mode = 0;
   bool has_mode = open_needs_mode(flags);
   if (has_mode) {
      va_list ap;
      va_start(ap, flags);
      mode = va_arg(ap, int);
      va_end(ap);
   }
   return call_open64_common(path, flags, mode, has_mode,
                             __builtin_return_address(0));
}

HOOK_EXPORT int __open_2(const char *path, int flags) {
   auto fn = resolve(real_open_2, "__open_2");
   if (!fn) {
      return call_open_common(path, flags, 0, false,
                              __builtin_return_address(0));
   }
   int fd = fn(path, flags);
   int saved_errno = errno;
   note_open(path, flags, fd, __builtin_return_address(0));
   errno = saved_errno;
   return fd;
}

HOOK_EXPORT int openat(int dirfd, const char *path, int flags, ...) {
   mode_t mode = 0;
   bool has_mode = open_needs_mode(flags);
   if (has_mode) {
      va_list ap;
      va_start(ap, flags);
      mode = va_arg(ap, int);
      va_end(ap);
   }
   return call_openat_common(dirfd, path, flags, mode, has_mode,
                             __builtin_return_address(0));
}

HOOK_EXPORT int __openat_2(int dirfd, const char *path, int flags) {
   auto fn = resolve(real_openat_2, "__openat_2");
   if (!fn) {
      return call_openat_common(dirfd, path, flags, 0, false,
                                __builtin_return_address(0));
   }
   int fd = fn(dirfd, path, flags);
   int saved_errno = errno;
   note_open(path, flags, fd, __builtin_return_address(0));
   errno = saved_errno;
   return fd;
}

// ---------------------------------------------------------------------------
// close
// ---------------------------------------------------------------------------

HOOK_EXPORT int close(int fd) {
   auto fn = resolve(real_close, "close");
   bool mali = is_mali_fd(fd);
   if (mali) {
      unregister_mali_fd(fd);
   }
   int r = fn ? fn(fd) : -1;
   int saved_errno = errno;
   if (mali) {
      if (r < 0) {
         register_mali_fd(fd);
      }
      mali_hook::LogBuilder("close")
          .i64("fd", fd)
          .i64("ret", r)
          .boolean("mali", true);
   }
   errno = saved_errno;
   return r;
}

HOOK_EXPORT int dup(int oldfd) {
   auto fn = resolve(real_dup, "dup");
   bool mali = is_mali_fd(oldfd);
   int newfd = fn ? fn(oldfd) : -1;
   int saved_errno = errno;
   if (mali && newfd >= 0) {
      register_mali_fd(newfd);
      note_fd_copy("dup", oldfd, newfd, 0, __builtin_return_address(0));
   }
   errno = saved_errno;
   return newfd;
}

HOOK_EXPORT int dup2(int oldfd, int newfd) {
   auto fn = resolve(real_dup2, "dup2");
   int r = fn ? fn(oldfd, newfd) : -1;
   int saved_errno = errno;
   if (r >= 0) {
      replace_fd_tracking(oldfd, r);
      note_fd_copy("dup2", oldfd, r, 0, __builtin_return_address(0));
   }
   errno = saved_errno;
   return r;
}

HOOK_EXPORT int dup3(int oldfd, int newfd, int flags) {
   auto fn = resolve(real_dup3, "dup3");
   int r = fn ? fn(oldfd, newfd, flags) : -1;
   int saved_errno = errno;
   if (r >= 0) {
      replace_fd_tracking(oldfd, r);
      note_fd_copy("dup3", oldfd, r, flags, __builtin_return_address(0));
   }
   errno = saved_errno;
   return r;
}

HOOK_EXPORT int fcntl(int fd, int cmd, ...) {
   auto fn = resolve(real_fcntl, "fcntl");
   long arg = 0;
   bool has_arg = !fcntl_has_no_arg(cmd);
   if (has_arg) {
      va_list ap;
      va_start(ap, cmd);
      arg = va_arg(ap, long);
      va_end(ap);
   }

   int r = fn ? (has_arg ? fn(fd, cmd, arg) : fn(fd, cmd)) : -1;
   int saved_errno = errno;
   if (r >= 0) {
      switch (cmd) {
      case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
      case F_DUPFD_CLOEXEC:
#endif
         if (is_mali_fd(fd)) {
            register_mali_fd(r);
            note_fd_copy("fcntl_dup", fd, r, cmd,
                         __builtin_return_address(0));
         }
         break;
      default:
         break;
      }
   }
   errno = saved_errno;
   return r;
}

// ---------------------------------------------------------------------------
// ioctl
// ---------------------------------------------------------------------------

HOOK_EXPORT int ioctl(int fd, int request, ...) {
   auto fn = resolve(real_ioctl, "ioctl");

   void *arg = nullptr;
   va_list ap;
   va_start(ap, request);
   arg = va_arg(ap, void *);
   va_end(ap);

   bool mali = is_mali_fd(fd);
   unsigned long ureq = (unsigned long)(unsigned)request;
   PendingAlloc pending;
   if (mali) {
      pending = read_pending_alloc(ureq, arg);
      note_ioctl_raw_blob(fd, ureq, arg, "ioctl_enter");
      note_ioctl_user_ptr_blobs(fd, ureq, arg);
      note_mem_import_ref(fd, ureq, arg);
      mali_hook::decode_pre_ioctl(fd, ureq, arg);
      if (ureq == (unsigned long)KBASE_IOCTL_CS_QUEUE_KICK ||
          ureq == (unsigned long)KBASE_IOCTL_KCPU_QUEUE_ENQUEUE) {
         dump_mmap_snapshots("before_submit");
      }
   }
   int r = fn ? fn(fd, request, arg) : -1;
   int saved_errno = errno;
   if (mali) {
      note_ioctl_raw_blob(fd, ureq, arg, "ioctl_exit");
      mali_hook::decode_post_ioctl(fd, ureq, arg, r, saved_errno);
      note_ioctl_side_effects(fd, ureq, arg, pending, r);
      if (ureq == (unsigned long)KBASE_IOCTL_CS_QUEUE_KICK ||
          ureq == (unsigned long)KBASE_IOCTL_KCPU_QUEUE_ENQUEUE) {
         dump_mmap_snapshots("after_submit");
      }
      errno = saved_errno;
   }
   return r;
}

// ---------------------------------------------------------------------------
// mmap / munmap
// ---------------------------------------------------------------------------

HOOK_EXPORT void *mmap(void *addr, size_t length, int prot, int flags, int fd,
                       off_t offset) {
   auto fn = resolve(real_mmap, "mmap");
   void *p = fn ? fn(addr, length, prot, flags, fd, offset) : MAP_FAILED;
   if (is_mali_fd(fd)) {
      mali_hook::LogBuilder ev("mmap");
      ev.i64("fd", fd)
          .u64("length", (uint64_t)length)
          .hex("prot", (uint64_t)(uint32_t)prot)
          .hex("flags", (uint64_t)(uint32_t)flags)
          .hex("offset", (uint64_t)offset)
          .hex("ret", (uint64_t)(uintptr_t)p);
      if (p == MAP_FAILED) {
         ev.i64("errno", errno);
      } else {
         mali_hook::shader_dump_note_mmap(fd, p, length, (uint64_t)offset,
                                          prot);
         note_mmap_region(fd, p, length, (uint64_t)offset, prot);
      }
   }
   return p;
}

HOOK_EXPORT void *mmap64(void *addr, size_t length, int prot, int flags,
                         int fd, off64_t offset) {
   auto fn = resolve(real_mmap64, "mmap64");
   void *p = fn ? fn(addr, length, prot, flags, fd, offset) : MAP_FAILED;
   if (is_mali_fd(fd)) {
      mali_hook::LogBuilder ev("mmap64");
      ev.i64("fd", fd)
          .u64("length", (uint64_t)length)
          .hex("prot", (uint64_t)(uint32_t)prot)
          .hex("flags", (uint64_t)(uint32_t)flags)
          .hex("offset", (uint64_t)offset)
          .hex("ret", (uint64_t)(uintptr_t)p);
      if (p == MAP_FAILED) {
         ev.i64("errno", errno);
      } else {
         mali_hook::shader_dump_note_mmap(fd, p, length, (uint64_t)offset,
                                          prot);
         note_mmap_region(fd, p, length, (uint64_t)offset, prot);
      }
   }
   return p;
}

HOOK_EXPORT int munmap(void *addr, size_t length) {
   auto fn = resolve(real_munmap, "munmap");
   mali_hook::shader_dump_note_munmap(addr, length);
   forget_mmap_region(addr, length);
   // We don't know which mmap this corresponds to without tracking
   // every mali-fd mmap. Log unconditionally and the offline
   // collector can filter by addr-range.
   mali_hook::LogBuilder("munmap")
       .hex("addr", (uint64_t)(uintptr_t)addr)
       .u64("length", (uint64_t)length);
   return fn ? fn(addr, length) : -1;
}
