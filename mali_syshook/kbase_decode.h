// Decode a kbase ioctl call into JSONL events.
//
// `decode_pre_ioctl` is called BEFORE invoking the real ioctl and
// emits one event with the input fields. `decode_post_ioctl` is
// called after, with the kernel's return code + errno, and emits a
// second event with output fields (where applicable). The split lets
// us see both shapes even when the kernel overwrites in-place via a
// union request struct.

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace mali_hook {

void decode_pre_ioctl(int fd, unsigned long request, const void *arg);
void decode_post_ioctl(int fd, unsigned long request, const void *arg,
                       int ret, int saved_errno);

// Returns the symbolic name for an ioctl NR, or nullptr for unknown.
const char *kbase_ioctl_name(unsigned long request);

} // namespace mali_hook
