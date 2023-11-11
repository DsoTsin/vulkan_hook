#include "log_jsonl.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define TAG "MALI_SYSHOOK"

namespace mali_hook {

namespace {

std::mutex g_write_mutex;
int g_log_fd = -1;
bool g_use_logcat = false;
bool g_initialised = false;

uint64_t monotonic_ns() {
   struct timespec ts;
   clock_gettime(CLOCK_MONOTONIC, &ts);
   return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint32_t current_tid() {
   return (uint32_t)syscall(SYS_gettid);
}

void open_log_file(const char *path) {
   int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
   if (fd < 0) {
      __android_log_print(ANDROID_LOG_WARN, TAG,
                          "log_init: cannot open %s: %s", path, strerror(errno));
      return;
   }
   g_log_fd = fd;
   __android_log_print(ANDROID_LOG_INFO, TAG,
                       "log_init: writing JSONL to %s (fd=%d)", path, fd);
}

} // namespace

void log_init() {
   std::lock_guard<std::mutex> guard(g_write_mutex);
   if (g_initialised) {
      return;
   }
   g_initialised = true;

   const char *path = getenv("MALI_HOOK_LOG");
   const char *logcat = getenv("MALI_HOOK_LOGCAT");

   // Defaults: file at /data/local/tmp/mali_hook.jsonl, no logcat
   // mirror (because mirror duplicates 4 KiB per call and trashes
   // the radio buffer fast).
   if (!path || !*path) {
      path = "/data/local/tmp/mali_hook.jsonl";
   }
   open_log_file(path);

   g_use_logcat = (logcat && *logcat && strcmp(logcat, "0") != 0);
   __android_log_print(ANDROID_LOG_INFO, TAG,
                       "log_init: pid=%d logcat=%d path=%s",
                       getpid(), g_use_logcat, path);
}

// ---------------------------------------------------------------------------

void LogBuilder::append_raw(const char *s, size_t n) {
   if (truncated_) {
      return;
   }
   if (len_ + n + 32 >= sizeof(buf_)) {
      truncated_ = true;
      return;
   }
   memcpy(buf_ + len_, s, n);
   len_ += n;
}

void LogBuilder::append_cstr(const char *s) {
   append_raw(s, strlen(s));
}

void LogBuilder::append_quoted(const char *s) {
   append_cstr("\"");
   if (s == nullptr) {
      append_cstr("(null)");
   } else {
      for (; *s && !truncated_; ++s) {
         unsigned char c = (unsigned char)*s;
         if (c == '"' || c == '\\') {
            char esc[2] = {'\\', (char)c};
            append_raw(esc, 2);
         } else if (c == '\n') {
            append_cstr("\\n");
         } else if (c == '\r') {
            append_cstr("\\r");
         } else if (c == '\t') {
            append_cstr("\\t");
         } else if (c < 0x20) {
            char esc[8];
            int n = snprintf(esc, sizeof(esc), "\\u%04x", c);
            append_raw(esc, n);
         } else {
            char ch = (char)c;
            append_raw(&ch, 1);
         }
      }
   }
   append_cstr("\"");
}

void LogBuilder::append_u64(uint64_t v) {
   char tmp[32];
   int n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
   append_raw(tmp, n);
}

void LogBuilder::append_i64(int64_t v) {
   char tmp[32];
   int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
   append_raw(tmp, n);
}

void LogBuilder::append_hex(uint64_t v) {
   char tmp[32];
   int n = snprintf(tmp, sizeof(tmp), "\"0x%llx\"", (unsigned long long)v);
   append_raw(tmp, n);
}

void LogBuilder::start_field(const char *name) {
   if (first_field_) {
      first_field_ = false;
   } else {
      append_cstr(",");
   }
   append_quoted(name);
   append_cstr(":");
}

LogBuilder::LogBuilder(const char *kind) {
   append_cstr("{");
   first_field_ = false; // we wrote nothing yet but next field is first
   // Header fields (no leading comma).
   append_quoted("ts");
   append_cstr(":");
   append_u64(monotonic_ns());
   append_cstr(",");
   append_quoted("tid");
   append_cstr(":");
   append_u64(current_tid());
   append_cstr(",");
   append_quoted("kind");
   append_cstr(":");
   append_quoted(kind);
   first_field_ = false;
}

LogBuilder::~LogBuilder() {
   if (!committed_) {
      commit();
   }
}

void LogBuilder::commit() {
   committed_ = true;
   if (truncated_) {
      append_cstr(",\"trunc\":1");
   }
   append_cstr("}\n");

   std::lock_guard<std::mutex> guard(g_write_mutex);
   if (g_log_fd >= 0) {
      ssize_t w = write(g_log_fd, buf_, len_);
      (void)w; // best-effort; log to logcat if it fails
   }
   if (g_use_logcat) {
      // Trim trailing newline for logcat.
      size_t n = len_;
      while (n > 0 && (buf_[n - 1] == '\n' || buf_[n - 1] == '\r')) {
         --n;
      }
      buf_[n] = '\0';
      __android_log_write(ANDROID_LOG_INFO, TAG, buf_);
   }
}

LogBuilder &LogBuilder::u64(const char *name, uint64_t v) {
   start_field(name);
   append_u64(v);
   return *this;
}

LogBuilder &LogBuilder::i64(const char *name, int64_t v) {
   start_field(name);
   append_i64(v);
   return *this;
}

LogBuilder &LogBuilder::hex(const char *name, uint64_t v) {
   start_field(name);
   append_hex(v);
   return *this;
}

LogBuilder &LogBuilder::str(const char *name, const char *v) {
   start_field(name);
   append_quoted(v);
   return *this;
}

LogBuilder &LogBuilder::boolean(const char *name, bool v) {
   start_field(name);
   append_cstr(v ? "true" : "false");
   return *this;
}

LogBuilder &LogBuilder::raw(const char *name, const char *json_value) {
   start_field(name);
   append_cstr(json_value);
   return *this;
}

LogBuilder &LogBuilder::obj_begin(const char *name) {
   start_field(name);
   append_cstr("{");
   first_field_ = true;
   return *this;
}

LogBuilder &LogBuilder::obj_end() {
   append_cstr("}");
   first_field_ = false;
   return *this;
}

LogBuilder &LogBuilder::bytes(const char *name, const void *p, size_t n,
                              size_t max_bytes) {
   start_field(name);
   append_cstr("\"");
   const unsigned char *bp = (const unsigned char *)p;
   size_t limit = n < max_bytes ? n : max_bytes;
   char hex[3];
   for (size_t i = 0; i < limit && !truncated_; ++i) {
      snprintf(hex, sizeof(hex), "%02x", bp[i]);
      append_raw(hex, 2);
   }
   if (n > limit) {
      char tail[24];
      int k = snprintf(tail, sizeof(tail), "...(+%zu)", n - limit);
      append_raw(tail, k);
   }
   append_cstr("\"");
   return *this;
}

} // namespace mali_hook
