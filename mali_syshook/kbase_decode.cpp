#include "kbase_decode.h"
#include "log_jsonl.h"

#include "mali_base_csf_kernel.h"
#include "mali_base_kernel.h"
#include "mali_kbase_csf_ioctl.h"
#include "mali_kbase_ioctl.h"

#include <linux/ioctl.h>
#include <stdint.h>
#include <string.h>

namespace mali_hook {

namespace {

// Pull just the (dir,nr,size) bits — we ignore type because for
// kbase it's always 0x80, but we still print it as the cmd_type
// field so unexpected types stand out in the log.
struct IocBits {
   unsigned dir;
   unsigned type;
   unsigned nr;
   unsigned size;
};

IocBits parse_request(unsigned long request) {
   IocBits b;
   b.dir = _IOC_DIR(request);
   b.type = _IOC_TYPE(request);
   b.nr = _IOC_NR(request);
   b.size = _IOC_SIZE(request);
   return b;
}

const char *dir_name(unsigned dir) {
   switch (dir) {
   case _IOC_NONE: return "NONE";
   case _IOC_WRITE: return "W";
   case _IOC_READ: return "R";
   case _IOC_READ | _IOC_WRITE: return "RW";
   default: return "?";
   }
}

// ---------------------------------------------------------------------------
// Per-ioctl decoders. Each operates on a known struct or union and
// adds fields to `b`. They never read past the buffer the kernel has
// agreed to (the size is encoded in the ioctl NR).
//
// The decoders for unions handle both in/out by being called from
// either the pre or post hook with the same pointer. Since the
// kernel overwrites the union in place, the pre hook sees in fields
// and the post hook sees out fields — we let the caller decide which
// side to print.
// ---------------------------------------------------------------------------

void decode_in_mem_alloc(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_alloc *p = (const kbase_ioctl_mem_alloc *)arg;
   const auto &in = p->in;
   b.u64("va_pages", in.va_pages)
       .u64("commit_pages", in.commit_pages)
       .hex("extension", in.extension)
       .hex("flags", in.flags);
}

void decode_out_mem_alloc(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_alloc *p = (const kbase_ioctl_mem_alloc *)arg;
   const auto &out = p->out;
   b.hex("out_flags", out.flags).hex("gpu_va", out.gpu_va);
}

#ifdef KBASE_IOCTL_MEM_ALLOC_EX
void decode_in_mem_alloc_ex(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_alloc_ex *p = (const kbase_ioctl_mem_alloc_ex *)arg;
   const auto &in = p->in;
   b.u64("va_pages", in.va_pages)
       .u64("commit_pages", in.commit_pages)
       .hex("extension", in.extension)
       .hex("flags", in.flags)
       .hex("fixed_address", in.fixed_address);
}

void decode_out_mem_alloc_ex(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_alloc_ex *p = (const kbase_ioctl_mem_alloc_ex *)arg;
   const auto &out = p->out;
   b.hex("out_flags", out.flags).hex("gpu_va", out.gpu_va);
}
#endif

void decode_in_mem_free(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_free *p = (const kbase_ioctl_mem_free *)arg;
   b.hex("gpu_addr", p->gpu_addr);
}

void decode_in_mem_import(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_import *p = (const kbase_ioctl_mem_import *)arg;
   const auto &in = p->in;
   b.hex("flags", in.flags).hex("phandle", in.phandle).u64("type", in.type);
}

void decode_out_mem_import(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_import *p = (const kbase_ioctl_mem_import *)arg;
   const auto &out = p->out;
   b.hex("flags", out.flags).hex("gpu_va", out.gpu_va).u64("va_pages", out.va_pages);
}

void decode_in_mem_sync(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_sync *p = (const kbase_ioctl_mem_sync *)arg;
   b.hex("handle", p->handle)
       .hex("user_addr", p->user_addr)
       .u64("size", p->size)
       .u64("type", p->type);
}

void decode_in_mem_commit(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_commit *p = (const kbase_ioctl_mem_commit *)arg;
   b.hex("gpu_addr", p->gpu_addr).u64("pages", p->pages);
}

void decode_in_mem_flags_change(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_flags_change *p =
       (const kbase_ioctl_mem_flags_change *)arg;
   b.hex("gpu_va", p->gpu_va).hex("flags", p->flags).hex("mask", p->mask);
}

void decode_in_mem_exec_init(LogBuilder &b, const void *arg) {
   const kbase_ioctl_mem_exec_init *p =
       (const kbase_ioctl_mem_exec_init *)arg;
   b.u64("va_pages", p->va_pages);
}

void decode_in_mem_jit_init(LogBuilder &b, const void *arg, unsigned size) {
   if (size >= sizeof(kbase_ioctl_mem_jit_init)) {
      const kbase_ioctl_mem_jit_init *p =
          (const kbase_ioctl_mem_jit_init *)arg;
      b.u64("va_pages", p->va_pages)
          .u64("max_allocations", p->max_allocations)
          .u64("trim_level", p->trim_level)
          .u64("group_id", p->group_id)
          .u64("phys_pages", p->phys_pages);
   } else if (size >= sizeof(kbase_ioctl_mem_jit_init_11_5)) {
      const kbase_ioctl_mem_jit_init_11_5 *p =
          (const kbase_ioctl_mem_jit_init_11_5 *)arg;
      b.u64("va_pages", p->va_pages)
          .u64("max_allocations", p->max_allocations)
          .u64("trim_level", p->trim_level)
          .u64("group_id", p->group_id);
   } else {
      const kbase_ioctl_mem_jit_init_10_2 *p =
          (const kbase_ioctl_mem_jit_init_10_2 *)arg;
      b.u64("va_pages", p->va_pages);
   }
}

void decode_in_set_flags(LogBuilder &b, const void *arg) {
   const kbase_ioctl_set_flags *p = (const kbase_ioctl_set_flags *)arg;
   b.hex("create_flags", p->create_flags);
}

void decode_in_version_check(LogBuilder &b, const void *arg) {
   const kbase_ioctl_version_check *p =
       (const kbase_ioctl_version_check *)arg;
   b.u64("in_major", p->major).u64("in_minor", p->minor);
}

void decode_out_version_check(LogBuilder &b, const void *arg) {
   const kbase_ioctl_version_check *p =
       (const kbase_ioctl_version_check *)arg;
   b.u64("major", p->major).u64("minor", p->minor);
}

void decode_in_gpuprops(LogBuilder &b, const void *arg) {
   const kbase_ioctl_get_gpuprops *p = (const kbase_ioctl_get_gpuprops *)arg;
   b.hex("buffer", p->buffer).u64("size", p->size).hex("flags", p->flags);
}

void decode_in_stream_create(LogBuilder &b, const void *arg) {
   const kbase_ioctl_stream_create *p =
       (const kbase_ioctl_stream_create *)arg;
   char name_buf[sizeof(p->name) + 1];
   memcpy(name_buf, p->name, sizeof(p->name));
   name_buf[sizeof(p->name)] = '\0';
   b.str("name", name_buf);
}

// ---- CSF -----------------------------------------------------------------

void decode_in_cs_tiler_heap_init(LogBuilder &b, const void *arg,
                                  unsigned size) {
   const kbase_ioctl_cs_tiler_heap_init *p =
       (const kbase_ioctl_cs_tiler_heap_init *)arg;
   const auto &in = p->in;
   b.hex("chunk_size", in.chunk_size)
       .u64("initial_chunks", in.initial_chunks)
       .u64("max_chunks", in.max_chunks)
       .u64("target_in_flight", in.target_in_flight)
       .u64("group_id", in.group_id);
   // UK 1.14+ extended the in-struct with `buf_desc_va`. Local
   // header is older; if the kernel hands us a 24-byte payload
   // pull the trailing 8 bytes manually.
   if (size >= sizeof(kbase_ioctl_cs_tiler_heap_init) + 8) {
      uint64_t buf_desc_va = 0;
      memcpy(&buf_desc_va,
             (const uint8_t *)arg + sizeof(kbase_ioctl_cs_tiler_heap_init),
             sizeof(buf_desc_va));
      b.hex("buf_desc_va", buf_desc_va);
   }
}

void decode_out_cs_tiler_heap_init(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_tiler_heap_init *p =
       (const kbase_ioctl_cs_tiler_heap_init *)arg;
   const auto &out = p->out;
   b.hex("gpu_heap_va", out.gpu_heap_va)
       .hex("first_chunk_va", out.first_chunk_va);
}

void decode_in_cs_tiler_heap_term(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_tiler_heap_term *p =
       (const kbase_ioctl_cs_tiler_heap_term *)arg;
   b.hex("gpu_heap_va", p->gpu_heap_va);
}

void decode_in_cs_queue_register(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_register *p =
       (const kbase_ioctl_cs_queue_register *)arg;
   b.hex("buffer_gpu_addr", p->buffer_gpu_addr)
       .u64("buffer_size", p->buffer_size)
       .u64("priority", p->priority);
}

void decode_in_cs_queue_register_ex(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_register_ex *p =
       (const kbase_ioctl_cs_queue_register_ex *)arg;
   b.hex("buffer_gpu_addr", p->buffer_gpu_addr)
       .u64("buffer_size", p->buffer_size)
       .u64("priority", p->priority)
       .hex("ex_offset_var_addr", p->ex_offset_var_addr)
       .hex("ex_buffer_base", p->ex_buffer_base)
       .u64("ex_buffer_size", p->ex_buffer_size)
       .u64("ex_event_size", p->ex_event_size)
       .u64("ex_event_state", p->ex_event_state);
}

void decode_in_cs_queue_kick(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_kick *p = (const kbase_ioctl_cs_queue_kick *)arg;
   b.hex("buffer_gpu_addr", p->buffer_gpu_addr);
}

void decode_in_cs_queue_bind(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_bind *p = (const kbase_ioctl_cs_queue_bind *)arg;
   const auto &in = p->in;
   b.hex("buffer_gpu_addr", in.buffer_gpu_addr)
       .u64("group_handle", in.group_handle)
       .u64("csi_index", in.csi_index);
}

void decode_out_cs_queue_bind(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_bind *p = (const kbase_ioctl_cs_queue_bind *)arg;
   const auto &out = p->out;
   b.hex("mmap_handle", out.mmap_handle);
}

void decode_in_cs_queue_terminate(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_terminate *p =
       (const kbase_ioctl_cs_queue_terminate *)arg;
   b.hex("buffer_gpu_addr", p->buffer_gpu_addr);
}

void decode_in_cs_group_create(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_group_create *p =
       (const kbase_ioctl_cs_queue_group_create *)arg;
   const auto &in = p->in;
   b.hex("tiler_mask", in.tiler_mask)
       .hex("fragment_mask", in.fragment_mask)
       .hex("compute_mask", in.compute_mask)
       .u64("cs_min", in.cs_min)
       .u64("priority", in.priority)
       .u64("tiler_max", in.tiler_max)
       .u64("fragment_max", in.fragment_max)
       .u64("compute_max", in.compute_max);
}

void decode_out_cs_group_create(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_group_create *p =
       (const kbase_ioctl_cs_queue_group_create *)arg;
   const auto &out = p->out;
   b.u64("group_handle", out.group_handle).u64("group_uid", out.group_uid);
}

void decode_in_cs_group_create_1_6(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_group_create_1_6 *p =
       (const kbase_ioctl_cs_queue_group_create_1_6 *)arg;
   const auto &in = p->in;
   b.hex("tiler_mask", in.tiler_mask)
       .hex("fragment_mask", in.fragment_mask)
       .hex("compute_mask", in.compute_mask)
       .u64("cs_min", in.cs_min)
       .u64("priority", in.priority)
       .u64("tiler_max", in.tiler_max)
       .u64("fragment_max", in.fragment_max)
       .u64("compute_max", in.compute_max);
}

void decode_out_cs_group_create_1_6(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_group_create_1_6 *p =
       (const kbase_ioctl_cs_queue_group_create_1_6 *)arg;
   const auto &out = p->out;
   b.u64("group_handle", out.group_handle).u64("group_uid", out.group_uid);
}

void decode_in_cs_group_terminate(LogBuilder &b, const void *arg) {
   const kbase_ioctl_cs_queue_group_term *p =
       (const kbase_ioctl_cs_queue_group_term *)arg;
   b.u64("group_handle", p->group_handle);
}

void decode_in_kcpu_new(LogBuilder &b, const void *arg) {
   const kbase_ioctl_kcpu_queue_new *p =
       (const kbase_ioctl_kcpu_queue_new *)arg;
   b.u64("id", p->id);
}

void decode_in_kcpu_delete(LogBuilder &b, const void *arg) {
   const kbase_ioctl_kcpu_queue_delete *p =
       (const kbase_ioctl_kcpu_queue_delete *)arg;
   b.u64("id", p->id);
}

void decode_in_kcpu_enqueue(LogBuilder &b, const void *arg) {
   const kbase_ioctl_kcpu_queue_enqueue *p =
       (const kbase_ioctl_kcpu_queue_enqueue *)arg;
   b.hex("addr", p->addr).u64("nr_commands", p->nr_commands).u64("id", p->id);
}

void decode_in_cs_event_signal(LogBuilder & /*b*/, const void * /*arg*/) {
   // Empty payload.
}

// ---- name + dispatch ----------------------------------------------------

struct Entry {
   unsigned long request;
   const char *name;
   void (*pre)(LogBuilder &, const void *);
   void (*post)(LogBuilder &, const void *);
   // Pre-decoders that need the kernel's encoded payload size (for
   // UAPI struct variants with different sizes — JIT_INIT, the
   // 1_13/post-1.14 tiler heap, etc.). When non-null, used in
   // preference to `pre`.
   void (*pre_sized)(LogBuilder &, const void *, unsigned);
};

void decode_post_default(LogBuilder &b, const void *arg);

#define DECLARE_IOCTL(REQ, PRE, POST)                                          \
   { (unsigned long)REQ, #REQ, PRE, POST, nullptr }
#define DECLARE_IOCTL_SIZED(REQ, PRE_SZ, POST)                                 \
   { (unsigned long)REQ, #REQ, nullptr, POST, PRE_SZ }

const Entry kEntries[] = {
    DECLARE_IOCTL(KBASE_IOCTL_VERSION_CHECK, decode_in_version_check,
                  decode_out_version_check),
    DECLARE_IOCTL(KBASE_IOCTL_VERSION_CHECK_RESERVED, decode_in_version_check,
                  decode_out_version_check),
    DECLARE_IOCTL(KBASE_IOCTL_SET_FLAGS, decode_in_set_flags, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_GET_GPUPROPS, decode_in_gpuprops, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_ALLOC, decode_in_mem_alloc,
                  decode_out_mem_alloc),
#ifdef KBASE_IOCTL_MEM_ALLOC_EX
    DECLARE_IOCTL(KBASE_IOCTL_MEM_ALLOC_EX, decode_in_mem_alloc_ex,
                  decode_out_mem_alloc_ex),
#endif
    DECLARE_IOCTL(KBASE_IOCTL_MEM_FREE, decode_in_mem_free, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_IMPORT, decode_in_mem_import,
                  decode_out_mem_import),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_SYNC, decode_in_mem_sync, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_COMMIT, decode_in_mem_commit, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_FLAGS_CHANGE, decode_in_mem_flags_change,
                  nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_EXEC_INIT, decode_in_mem_exec_init, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_STREAM_CREATE, decode_in_stream_create, nullptr),

    DECLARE_IOCTL_SIZED(KBASE_IOCTL_CS_TILER_HEAP_INIT,
                        decode_in_cs_tiler_heap_init,
                        decode_out_cs_tiler_heap_init),
    DECLARE_IOCTL(KBASE_IOCTL_CS_TILER_HEAP_TERM, decode_in_cs_tiler_heap_term,
                  nullptr),

    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_REGISTER, decode_in_cs_queue_register,
                  nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_REGISTER_EX,
                  decode_in_cs_queue_register_ex, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_KICK, decode_in_cs_queue_kick, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_BIND, decode_in_cs_queue_bind,
                  decode_out_cs_queue_bind),
    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_TERMINATE, decode_in_cs_queue_terminate,
                  nullptr),

    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE, decode_in_cs_group_create,
                  decode_out_cs_group_create),
    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6,
                  decode_in_cs_group_create_1_6,
                  decode_out_cs_group_create_1_6),
    DECLARE_IOCTL(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE,
                  decode_in_cs_group_terminate, nullptr),

    DECLARE_IOCTL(KBASE_IOCTL_CS_EVENT_SIGNAL, decode_in_cs_event_signal,
                  nullptr),

    DECLARE_IOCTL(KBASE_IOCTL_KCPU_QUEUE_CREATE, nullptr, decode_in_kcpu_new),
    DECLARE_IOCTL(KBASE_IOCTL_KCPU_QUEUE_DELETE, decode_in_kcpu_delete,
                  nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, decode_in_kcpu_enqueue,
                  nullptr),

    // Names-only — we don't decode the payload, but we still print
    // the matched name and the raw size.
    DECLARE_IOCTL(KBASE_IOCTL_GET_DDK_VERSION, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_GET_CONTEXT_ID, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_TLSTREAM_ACQUIRE, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_TLSTREAM_FLUSH, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_FENCE_VALIDATE, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_PROFILE_ADD, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_STICKY_RESOURCE_MAP, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_STICKY_RESOURCE_UNMAP, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_QUERY, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_ALIAS, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_FIND_CPU_OFFSET, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_CONTEXT_PRIORITY_CHECK, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_SET_LIMITED_CORE_COUNT, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_CS_GET_GLB_IFACE, nullptr, nullptr),
    DECLARE_IOCTL(KBASE_IOCTL_CS_CPU_QUEUE_DUMP, nullptr, nullptr),

    // Wire the JIT_INIT variants through the sized decoder. The
    // local UAPI may carry any of the three struct shapes; only the
    // size distinguishes them.
    DECLARE_IOCTL_SIZED(KBASE_IOCTL_MEM_JIT_INIT, decode_in_mem_jit_init,
                        nullptr),
    DECLARE_IOCTL_SIZED(KBASE_IOCTL_MEM_JIT_INIT_11_5, decode_in_mem_jit_init,
                        nullptr),
    DECLARE_IOCTL_SIZED(KBASE_IOCTL_MEM_JIT_INIT_10_2, decode_in_mem_jit_init,
                        nullptr),
};

const Entry *find_entry(unsigned long request) {
   for (const Entry &e : kEntries) {
      if (e.request == request) {
         return &e;
      }
   }
   // Same NR/type but different size (UAPI drift between BSPs).
   // Fall back to matching on type+nr only.
   unsigned type = _IOC_TYPE(request);
   unsigned nr = _IOC_NR(request);
   for (const Entry &e : kEntries) {
      if (_IOC_TYPE(e.request) == type && _IOC_NR(e.request) == nr) {
         return &e;
      }
   }
   return nullptr;
}

} // namespace

const char *kbase_ioctl_name(unsigned long request) {
   const Entry *e = find_entry(request);
   return e ? e->name : nullptr;
}

void decode_pre_ioctl(int fd, unsigned long request, const void *arg) {
   IocBits b = parse_request(request);
   const Entry *e = find_entry(request);

   LogBuilder ev("ioctl_enter");
   ev.i64("fd", fd);
   ev.hex("cmd", request);
   ev.str("name", e ? e->name : "UNKNOWN");
   ev.str("dir", dir_name(b.dir));
   ev.u64("nr", b.nr);
   ev.u64("size", b.size);
   if (b.type != 0x80) {
      ev.u64("type", b.type);
   }

   if (e && e->pre_sized) {
      ev.obj_begin("in");
      e->pre_sized(ev, arg, b.size);
      ev.obj_end();
   } else if (e && e->pre) {
      ev.obj_begin("in");
      e->pre(ev, arg);
      ev.obj_end();
   } else if (arg && b.size > 0 && (b.dir & _IOC_WRITE)) {
      // Hex-dump the bytes the userspace would send to the kernel.
      ev.bytes("in_raw", arg, b.size);
   }
}

void decode_post_default(LogBuilder & /*b*/, const void * /*arg*/) {}

void decode_post_ioctl(int fd, unsigned long request, const void *arg, int ret,
                       int saved_errno) {
   IocBits b = parse_request(request);
   const Entry *e = find_entry(request);

   LogBuilder ev("ioctl_exit");
   ev.i64("fd", fd);
   ev.hex("cmd", request);
   ev.str("name", e ? e->name : "UNKNOWN");
   ev.i64("ret", ret);
   if (ret < 0) {
      ev.i64("errno", saved_errno);
   }

   if (e && e->post && ret >= 0) {
      ev.obj_begin("out");
      e->post(ev, arg);
      ev.obj_end();
   } else if (arg && b.size > 0 && (b.dir & _IOC_READ) && ret >= 0 && !e) {
      ev.bytes("out_raw", arg, b.size);
   }
}

} // namespace mali_hook
