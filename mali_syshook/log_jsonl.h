// Tiny JSONL writer.
//
// Each event is a single line of JSON terminated with '\n'. Output
// goes to a file specified by env var `MALI_HOOK_LOG=/path` and/or
// logcat (`MALI_HOOK_LOGCAT=1` to enable). When neither is set the
// file path defaults to `/data/local/tmp/mali_hook.jsonl`.
//
// LogBuilder accumulates a single event in a fixed-size stack buffer.
// On destruction it acquires a global mutex, writes the line, then
// releases. Concurrent threads serialise on the write, never on
// formatting. The fixed buffer (4 KiB) is enough for every kbase
// ioctl we care about; if an event ever overflows it is silently
// truncated and tagged with `"trunc":1`.

#pragma once

#include <stdint.h>
#include <stddef.h>

namespace mali_hook {

void log_init();

class LogBuilder {
   char buf_[4096];
   size_t len_ = 0;
   bool first_field_ = true;
   bool truncated_ = false;
   bool committed_ = false;

   void append_raw(const char *s, size_t n);
   void append_cstr(const char *s);
   void append_quoted(const char *s);
   void append_u64(uint64_t v);
   void append_i64(int64_t v);
   void append_hex(uint64_t v);
   void start_field(const char *name);

 public:
   explicit LogBuilder(const char *kind);
   ~LogBuilder();

   LogBuilder &u64(const char *name, uint64_t v);
   LogBuilder &i64(const char *name, int64_t v);
   LogBuilder &hex(const char *name, uint64_t v);
   LogBuilder &str(const char *name, const char *v);
   LogBuilder &boolean(const char *name, bool v);

   // Emits a raw JSON value (caller-validated). Use sparingly — the
   // typed accessors above are preferred. The string is copied
   // verbatim without quoting; pass `"null"`, `[1,2,3]`, `{"k":1}`,
   // etc.
   LogBuilder &raw(const char *name, const char *json_value);

   // Nested object — call obj_end() to close. Pairs of begin/end
   // must balance; the destructor will close any leftover braces.
   LogBuilder &obj_begin(const char *name);
   LogBuilder &obj_end();

   // Hex byte array (e.g. for unknown ioctl payloads). Limits to
   // `max_bytes` to keep events readable.
   LogBuilder &bytes(const char *name, const void *p, size_t n,
                     size_t max_bytes = 128);

   // Manually commit before destruction (rarely needed).
   void commit();
};

} // namespace mali_hook
