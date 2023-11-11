#include "shader_dump.h"
#include "log_jsonl.h"
#include "mali_base_kernel.h"
#include "mali_base_csf_kernel.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>

#define TAG "MALI_SYSHOOK"

namespace mali_hook {

namespace {

struct ExecBo {
   int fd = -1;
   uint64_t gpu_va = 0;
   uint64_t flags = 0;
   uint64_t alloc_size = 0;
   uint8_t *cpu = nullptr;
   size_t cpu_size = 0;
   int prot = 0;
   uint64_t last_hash = 0;
   size_t last_size = 0;
   uint64_t last_seq = 0;
   char last_path[768] = {};
   bool dumped = false;
};

std::mutex g_mutex;
std::unordered_map<uint64_t, ExecBo> g_exec_bos;
uint64_t g_dump_seq = 0;

bool enabled() {
   static bool v = []() {
      const char *env = getenv("MALI_HOOK_ISA_DUMP");
      return env && *env && strcmp(env, "0") != 0;
   }();
   return v;
}

size_t max_dump_bytes() {
   static size_t v = []() -> size_t {
      const char *env = getenv("MALI_HOOK_ISA_MAX_BYTES");
      if (!env || !*env) {
         return 1024 * 1024;
      }
      unsigned long long n = strtoull(env, nullptr, 0);
      return n ? (size_t)n : (size_t)(1024 * 1024);
   }();
   return v;
}

bool mkdir_one(const char *path) {
   if (!path || !*path) {
      return false;
   }
   if (mkdir(path, 0755) == 0 || errno == EEXIST) {
      return true;
   }
   return false;
}

void mkdirs(char *path) {
   if (!path || !*path) {
      return;
   }
   for (char *p = path + 1; *p; ++p) {
      if (*p == '/') {
         *p = '\0';
         mkdir_one(path);
         *p = '/';
      }
   }
   mkdir_one(path);
}

const char *output_dir() {
   static char dir[512];
   static bool init = false;
   if (init) {
      return dir;
   }
   init = true;

   const char *env = getenv("MALI_HOOK_ISA_DIR");
   if (env && *env) {
      snprintf(dir, sizeof(dir), "%s", env);
   } else {
      const char *log = getenv("MALI_HOOK_LOG");
      if (log && *log) {
         const char *slash = strrchr(log, '/');
         if (slash && slash != log) {
            size_t n = (size_t)(slash - log);
            if (n > sizeof(dir) - 16) {
               n = sizeof(dir) - 16;
            }
            memcpy(dir, log, n);
            dir[n] = '\0';
            strncat(dir, "/shader_isa", sizeof(dir) - strlen(dir) - 1);
         }
      }
      if (!dir[0]) {
         snprintf(dir, sizeof(dir), "/data/local/tmp/mali_shader_isa");
      }
   }

   char tmp[sizeof(dir)];
   snprintf(tmp, sizeof(tmp), "%s", dir);
   mkdirs(tmp);
   return dir;
}

uint64_t hash64(const void *data, size_t size) {
   const uint8_t *p = (const uint8_t *)data;
   uint64_t h = 1469598103934665603ull;
   for (size_t i = 0; i < size; ++i) {
      h ^= p[i];
      h *= 1099511628211ull;
   }
   return h;
}

bool all_zero(const uint8_t *p, size_t size) {
   for (size_t i = 0; i < size; ++i) {
      if (p[i] != 0) {
         return false;
      }
   }
   return true;
}

void dump_one_locked(ExecBo &bo, const char *reason,
                     const char *context_json = nullptr) {
   if (!enabled() || !bo.cpu || !bo.cpu_size) {
      return;
   }
   size_t bytes = bo.cpu_size;
   size_t max_bytes = max_dump_bytes();
   if (bytes > max_bytes) {
      bytes = max_bytes;
   }
   if (bytes == 0 || all_zero(bo.cpu, bytes)) {
      return;
   }

   uint64_t hash = hash64(bo.cpu, bytes);
   if (bo.dumped && bo.last_hash == hash && bo.last_size == bytes) {
      if (context_json && *context_json && bo.last_path[0]) {
         LogBuilder ev("shader_isa_dump_ref");
         ev.str("reason", reason ? reason : "")
             .str("path", bo.last_path)
             .hex("gpu_va", bo.gpu_va)
             .hex("flags", bo.flags)
             .hex("cpu", (uint64_t)(uintptr_t)bo.cpu)
             .u64("bytes", bytes)
             .u64("allocSize", bo.alloc_size)
             .hex("hash", hash)
             .u64("seq", bo.last_seq)
             .raw("spirvContext", context_json);
      }
      return;
   }

   char path[768];
   uint64_t seq = ++g_dump_seq;
   snprintf(path, sizeof(path), "%s/isa_%05llu_gpu_%llx_%zu_%016llx.bin",
            output_dir(), (unsigned long long)seq,
            (unsigned long long)bo.gpu_va, bytes, (unsigned long long)hash);

   int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
   int saved_errno = errno;
   if (fd >= 0) {
      const uint8_t *p = bo.cpu;
      size_t left = bytes;
      while (left) {
         ssize_t n = write(fd, p, left);
         if (n <= 0) {
            saved_errno = errno;
            break;
         }
         p += n;
         left -= (size_t)n;
      }
      close(fd);
      if (left == 0) {
         bo.last_hash = hash;
         bo.last_size = bytes;
         bo.last_seq = seq;
         snprintf(bo.last_path, sizeof(bo.last_path), "%s", path);
         bo.dumped = true;
         LogBuilder ev("shader_isa_dump");
         ev.str("reason", reason ? reason : "")
             .str("path", path)
             .hex("gpu_va", bo.gpu_va)
             .hex("flags", bo.flags)
             .hex("cpu", (uint64_t)(uintptr_t)bo.cpu)
             .u64("bytes", bytes)
             .u64("allocSize", bo.alloc_size)
             .hex("hash", hash)
             .u64("seq", seq);
         if (context_json && *context_json) {
            ev.raw("spirvContext", context_json);
         }
         return;
      }
   }

   __android_log_print(ANDROID_LOG_WARN, TAG,
                       "shader ISA dump failed path=%s errno=%d", path,
                       saved_errno);
   LogBuilder("shader_isa_dump_error")
       .str("reason", reason ? reason : "")
       .str("path", path)
       .hex("gpu_va", bo.gpu_va)
       .i64("errno", saved_errno);
}

bool is_exec(uint64_t flags) {
   return (flags & BASE_MEM_PROT_GPU_EX) != 0;
}

} // namespace

void shader_dump_note_alloc(int fd, uint64_t gpu_va, uint64_t flags,
                            uint64_t size) {
   if (!enabled() || !is_exec(flags) || !gpu_va) {
      return;
   }
   std::lock_guard<std::mutex> g(g_mutex);
   ExecBo &bo = g_exec_bos[gpu_va];
   bo.fd = fd;
   bo.gpu_va = gpu_va;
   bo.flags = flags;
   bo.alloc_size = size;
}

void shader_dump_note_flags_change(uint64_t gpu_va, uint64_t flags,
                                   uint64_t mask) {
   if (!enabled() || !gpu_va || (mask & BASE_MEM_PROT_GPU_EX) == 0) {
      return;
   }
   std::lock_guard<std::mutex> g(g_mutex);
   if (is_exec(flags)) {
      ExecBo &bo = g_exec_bos[gpu_va];
      bo.gpu_va = gpu_va;
      bo.flags = (bo.flags & ~mask) | (flags & mask);
   } else {
      g_exec_bos.erase(gpu_va);
   }
}

void shader_dump_note_free(uint64_t gpu_va) {
   if (!enabled() || !gpu_va) {
      return;
   }
   std::lock_guard<std::mutex> g(g_mutex);
   auto it = g_exec_bos.find(gpu_va);
   if (it != g_exec_bos.end()) {
      dump_one_locked(it->second, "mem_free");
      g_exec_bos.erase(it);
   }
}

void shader_dump_note_mmap(int fd, void *cpu, size_t length, uint64_t offset,
                           int prot) {
   if (!enabled() || !cpu || !length) {
      return;
   }
   std::lock_guard<std::mutex> g(g_mutex);
   auto it = g_exec_bos.find(offset);
   if (it == g_exec_bos.end()) {
      return;
   }
   it->second.fd = fd;
   it->second.cpu = (uint8_t *)cpu;
   it->second.cpu_size = length;
   it->second.prot = prot;
}

void shader_dump_note_munmap(void *cpu, size_t length) {
   if (!enabled() || !cpu || !length) {
      return;
   }
   std::lock_guard<std::mutex> g(g_mutex);
   uintptr_t start = (uintptr_t)cpu;
   uintptr_t end = start + length;
   for (auto it = g_exec_bos.begin(); it != g_exec_bos.end(); ++it) {
      uintptr_t bo_start = (uintptr_t)it->second.cpu;
      uintptr_t bo_end = bo_start + it->second.cpu_size;
      if (bo_start && bo_start < end && start < bo_end) {
         dump_one_locked(it->second, "munmap");
         it->second.cpu = nullptr;
         it->second.cpu_size = 0;
      }
   }
}

bool shader_dump_enabled() { return enabled(); }

uint64_t shader_dump_hash64(const void *data, size_t size) {
   return hash64(data, size);
}

const char *shader_dump_output_dir() { return output_dir(); }

void shader_dump_dump_all(const char *reason) {
   shader_dump_dump_all_with_context(reason, nullptr);
}

void shader_dump_dump_all_with_context(const char *reason,
                                       const char *context_json) {
   if (!enabled()) {
      return;
   }
   std::lock_guard<std::mutex> g(g_mutex);
   for (auto &kv : g_exec_bos) {
      dump_one_locked(kv.second, reason, context_json);
   }
}

size_t shader_dump_collect_infos(ShaderIsaDumpInfo *out_infos, size_t cap) {
   if (!enabled()) {
      return 0;
   }
   std::lock_guard<std::mutex> g(g_mutex);
   size_t total = 0;
   for (auto &kv : g_exec_bos) {
      const ExecBo &bo = kv.second;
      if (!bo.dumped || !bo.last_path[0]) {
         continue;
      }
      if (out_infos && total < cap) {
         ShaderIsaDumpInfo &info = out_infos[total];
         info.gpu_va = bo.gpu_va;
         info.flags = bo.flags;
         info.cpu = (uint64_t)(uintptr_t)bo.cpu;
         info.alloc_size = bo.alloc_size;
         info.hash = bo.last_hash;
         info.seq = bo.last_seq;
         info.bytes = bo.last_size;
         snprintf(info.path, sizeof(info.path), "%s", bo.last_path);
      }
      total++;
   }
   return total;
}

} // namespace mali_hook
