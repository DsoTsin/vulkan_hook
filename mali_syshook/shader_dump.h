// Dump executable kbase BO contents for offline Mali ISA analysis.

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace mali_hook {

struct ShaderIsaDumpInfo {
   uint64_t gpu_va = 0;
   uint64_t flags = 0;
   uint64_t cpu = 0;
   uint64_t alloc_size = 0;
   uint64_t hash = 0;
   uint64_t seq = 0;
   size_t bytes = 0;
   char path[768] = {};
};

void shader_dump_note_alloc(int fd, uint64_t gpu_va, uint64_t flags,
                            uint64_t size);
void shader_dump_note_flags_change(uint64_t gpu_va, uint64_t flags,
                                   uint64_t mask);
void shader_dump_note_free(uint64_t gpu_va);
void shader_dump_note_mmap(int fd, void *cpu, size_t length, uint64_t offset,
                           int prot);
void shader_dump_note_munmap(void *cpu, size_t length);
bool shader_dump_enabled();
uint64_t shader_dump_hash64(const void *data, size_t size);
const char *shader_dump_output_dir();
void shader_dump_dump_all(const char *reason);
void shader_dump_dump_all_with_context(const char *reason,
                                       const char *context_json);
size_t shader_dump_collect_infos(ShaderIsaDumpInfo *out_infos, size_t cap);

} // namespace mali_hook
