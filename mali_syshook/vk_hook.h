// Vulkan entry-point tracing.
//
// We export `vkGetInstanceProcAddr` / `vkGetDeviceProcAddr` and a
// curated set of high-traffic entry points. The exports shadow the
// loader's symbols in the app's link namespace, so the app's calls
// land here first. Each wrapper formats a JSONL enter event, calls
// through to the real function (resolved via the original loader
// GIPA/GDPA), then formats an exit event with the return code and
// any output handles.

#pragma once

namespace mali_hook {

void vk_hook_init();

} // namespace mali_hook
