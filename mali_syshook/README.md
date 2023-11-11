# mali_syshook

LD_PRELOAD-based tracer that captures the Vulkan-to-kbase interaction
of any Android process. Emits one JSON event per syscall / Vulkan
entry point.

## Build

```bat
build_android.bat
```

Requires NDK at `F:\Android\Sdk\ndk\25.1.8937393` (edit the script if
yours lives elsewhere). Output: `build-android\libmali_syshook.so`.

## Deploy and run

```bat
adb push build-android\libmali_syshook.so /data/local/tmp/
adb shell "chmod 0644 /data/local/tmp/libmali_syshook.so"
```

Run the victim with LD_PRELOAD. The hook writes JSONL to
`/data/local/tmp/mali_hook.jsonl` by default.

```bat
rem trace the system Vulkan info command
adb shell "LD_PRELOAD=/data/local/tmp/libmali_syshook.so cmd gpu vkjson"
adb pull /data/local/tmp/mali_hook.jsonl

rem trace your own probe
adb shell "LD_PRELOAD=/data/local/tmp/libmali_syshook.so MALI_HOOK_LOG=/data/local/tmp/manet.jsonl /data/local/tmp/manet/vulkan_probe_android"
```

`cmd gpu vkjson` may query Vulkan through Android system services and can
produce no in-process kbase events. For driver bring-up, prefer a process-local
probe or sample binary that calls the Vulkan loader in the same process.

Environment variables:

Additional Android tracing variables are documented in this table; keep
`wrap.sh` with Unix LF line endings when package-wrapping an APK.

| name              | default                              | meaning                                            |
| ----------------- | ------------------------------------ | -------------------------------------------------- |
| `MALI_HOOK_LOG`   | `/data/local/tmp/mali_hook.jsonl`    | output file. Set empty to disable file output.    |
| `MALI_HOOK_LOGCAT` | unset (off)                          | non-empty → mirror every event to `logcat -s MALI_SYSHOOK`. |

Extra variables:

- `MALI_HOOK_MAX_FRAMES`: default `0` (disabled). Stop the process after
  this many presented frames.
- `MALI_HOOK_HMI_SO_DELTA`: default `0x731000`. RK3588 HMI hint; add this
  to Android `libvulkan.so` procaddr offsets to get the corresponding
  `libGLES_mali.so` label offset.
- `MALI_HOOK_ISA_DUMP`: default `0` (disabled). Set to `1` to dump CPU
  visible kbase BOs allocated with `BASE_MEM_PROT_GPU_EX`.
- `MALI_HOOK_ISA_DIR`: default is `shader_isa` beside `MALI_HOOK_LOG`, or
  `/data/local/tmp/mali_shader_isa` when no log path is set.
- `MALI_HOOK_ISA_MAX_BYTES`: default `1048576`. Maximum bytes written per
  executable BO dump.

## Event format

Every event is a JSON object on its own line. Fields:

| field   | meaning                                           |
| ------- | ------------------------------------------------- |
| `ts`    | monotonic timestamp in nanoseconds.               |
| `tid`   | thread id (`gettid()`).                           |
| `kind`  | one of `open`, `fd_copy`, `close`, `ioctl_enter`, `ioctl_exit`, `mmap`, `mmap64`, `munmap`, `vk_procaddr`, `vk_enter`, `vk_exit`, `trace_stop`. |

Per-kind extras:

- `fd_copy` - `op`, `oldfd`, `newfd`, `flags?`.

- `open` — `path`, `flags`, `fd`, `mali` (bool), `errno?`.
- `ioctl_enter` — `fd`, `cmd`, `name`, `dir`, `nr`, `size`, `in?` (decoded struct).
- `ioctl_exit` — `fd`, `cmd`, `name`, `ret`, `errno?`, `out?` (decoded struct).
- `mmap` / `mmap64` — `fd`, `length`, `prot`, `flags`, `offset`, `ret`, `errno?`.
- `munmap` — `addr`, `length`.
- `vk_enter` — `fn` (function name) plus a small set of input fields.
- `vk_exit` — `fn`, `result`, plus output handles where applicable.

Additional binary dump events:

- `shader_isa_dump` - `reason`, `path`, `gpu_va`, `flags`, `cpu`, `bytes`,
  `allocSize`, `hash`, `seq`, optional `spirvContext`. Emitted only when
  `MALI_HOOK_ISA_DUMP=1`.
- `shader_isa_dump_ref` - same ISA metadata plus `spirvContext`, emitted when
  the executable BO content was already dumped and the hook only needs to attach
  a new pipeline/SPIR-V context to the existing ISA file.
- `shader_isa_dump_error` - failed binary dump with `path`, `gpu_va`,
  `errno`.
- `shader_spirv_dump` - SPIR-V module binary copied from
  `vkCreateShaderModule`, with `module`, `path`, `bytes`, and `hash`.
- `shader_spirv_dump_error` - failed SPIR-V file write.
- `shader_isa_spirv_map` - pipeline creation event with `fn`, `result`, and
  raw `spirvContext`.
- `shader_isa_spirv_table` - table summary for one pipeline creation. Fields
  include `pipeline`, `isaCount`, `isaEmitted`, `stageCount`, `stageEmitted`,
  `rowCount`, and `rowKind`.
- `shader_isa_spirv_relation` - one JSON row in the ISA/SPIR-V relation table.
  Each row contains `isaPath`, `isaHash`, `isaGpuVa`, `isaBytes`, `isaSeq`,
  `pipelineIndex`, `stageIndex`, `stage`, `entry`, `module`, `spirvPath`,
  `spirvHash`, and `spirvBytes` when the SPIR-V module was captured.

`spirvContext` is a compact JSON object used to correlate executable BO
snapshots with the Vulkan shader inputs that produced them. It records pipeline
type, create-info count, and a bounded stage list. Each stage includes
`pipelineIndex`, optional `stageIndex`, `stage`, `entry`, `module`, and when the
module was observed, `spirvPath`, `spirvHash`, and `spirvBytes`.

The SPIR-V and ISA binaries are written into `MALI_HOOK_ISA_DIR` so an offline
check can pair:

```text
shader_isa_dump.path / shader_isa_dump_ref.path + hash
  -> spirvContext.stages[].spirvPath + spirvHash
```

For scripts, prefer `shader_isa_spirv_relation`: it is already a row-oriented
JSON table and avoids large nested JSON values being truncated by the per-event
buffer.

Additional Vulkan procaddr fields:

- `vk_procaddr` is emitted from `dlsym`, `vkGetInstanceProcAddr`, and
  `vkGetDeviceProcAddr`. It records the proc name, dispatch handle,
  returned hook pointer, and module-relative offsets for the real loader
  pointer.
- `vk_procaddr.real` is an absolute process virtual address. Use
  `realModule` plus `realSoOffset` for stable cross-run analysis.
- `returned` points at `libmali_syshook.so` when the API is wrapped by
  this hook.

On the current RK3588 Android image, Vulkan is reached through Android's
HMI/HAL path. Many procaddr results are Android loader trampolines in
`/system/lib64/libvulkan.so`, not direct function starts inside
`/vendor/lib64/egl/libGLES_mali.so`. For those rows the hook also emits:

- `driverModuleHint`: currently `libGLES_mali.so`.
- `driverSoOffset`: `realSoOffset + MALI_HOOK_HMI_SO_DELTA`.
- `driverOffsetDelta`: the delta used, default `0x731000`.
- `driverOffsetSource`: `android_hmi_realSoOffset_plus_delta`.

The `driverSoOffset` value is good for IDA labels and comments in the
RK3588 stock `libGLES_mali.so`. It is not proof that the address is an
independent C/C++ function entry.

### IDA trace import notes

For `C:\Users\Station\Desktop\mali\rk3588\libGLES_mali.so`, the captured
computeraytracing trace produced Vulkan labels such as:

- `vkCreateGraphicsPipelines`: `0x74b668`
- `vkCreateComputePipelines`: `0x74b690`
- `vkCreateFramebuffer`: `0x74b860`
- `vkCreateRenderPass`: `0x74b8a0`
- `vkCreateSwapchainKHR`: `0x7553e0`
- `vkAcquireNextImageKHR`: `0x756548`
- `vkQueuePresentKHR`: `0x7568f8`

Use these as labels/comments at the exact addresses. Do not blindly force
all of them into IDA function starts. Several offsets live inside larger
shared dispatch/marshalling functions, for example `sub_74A700`,
`sub_74B740`, `sub_74BE08`, `sub_755370`, and `sub_756614`. Splitting all
trace labels into functions makes Hex-Rays produce `JUMPOUT` because the
control flow legitimately crosses those labels. Keep the large function
boundaries for decompilation quality, and use the `vk*` names as internal
navigation labels.

## Coverage

### kbase ioctls (fully decoded)

`VERSION_CHECK`, `SET_FLAGS`, `GET_GPUPROPS`, `MEM_ALLOC`, `MEM_ALLOC_EX`,
`MEM_FREE`, `MEM_IMPORT`, `MEM_SYNC`, `MEM_COMMIT`, `MEM_FLAGS_CHANGE`,
`MEM_EXEC_INIT`, `MEM_JIT_INIT` (+ 10_2 / 11_5 variants), `STREAM_CREATE`,
`CS_TILER_HEAP_INIT` (+ 1_13), `CS_TILER_HEAP_TERM`, `CS_QUEUE_REGISTER`,
`CS_QUEUE_REGISTER_EX`, `CS_QUEUE_KICK`, `CS_QUEUE_BIND`,
`CS_QUEUE_TERMINATE`, `CS_QUEUE_GROUP_CREATE` (+ 1_6),
`CS_QUEUE_GROUP_TERMINATE`, `CS_EVENT_SIGNAL`, `KCPU_QUEUE_CREATE`,
`KCPU_QUEUE_DELETE`, `KCPU_QUEUE_ENQUEUE`.

### kbase ioctls (named only, body hex-dumped)

`GET_DDK_VERSION`, `GET_CONTEXT_ID`, `TLSTREAM_*`, `FENCE_VALIDATE`,
`MEM_PROFILE_ADD`, `STICKY_RESOURCE_*`, `MEM_QUERY`, `MEM_ALIAS`,
`MEM_FIND_*`, `CONTEXT_PRIORITY_CHECK`, `SET_LIMITED_CORE_COUNT`,
`CS_GET_GLB_IFACE`, `CS_CPU_QUEUE_DUMP`.

Unknown ioctls (still on a mali fd) fall through to a hex-dump
labelled `UNKNOWN`.

### Vulkan entry points (wrapped)

`vkCreateInstance`, `vkDestroyInstance`, `vkEnumeratePhysicalDevices`,
`vkCreateDevice`, `vkDestroyDevice`, `vkAllocateMemory`, `vkFreeMemory`,
`vkMapMemory`, `vkFlushMappedMemoryRanges`, `vkBindBufferMemory`,
`vkBindImageMemory`,
`vkCreateBuffer`, `vkCreateImage`, `vkCreateImageView`,
`vkCreateShaderModule`, `vkCreateDescriptorSetLayout`,
`vkCreatePipelineLayout`, `vkCreateRenderPass`, `vkCreateFramebuffer`,
`vkCreateComputePipelines`, `vkCreateGraphicsPipelines`,
`vkCreateCommandPool`, `vkCreateSemaphore`, `vkCreateFence`,
`vkCreateSampler`, `vkCreateSwapchainKHR`, `vkAllocateCommandBuffers`,
`vkBeginCommandBuffer`, `vkEndCommandBuffer`, `vkCmdBindPipeline`,
`vkCmdBindDescriptorSets`, `vkCmdDispatch`, `vkCmdPipelineBarrier`,
`vkCmdCopyBufferToImage`, `vkCmdCopyImage`,
`vkQueueSubmit`, `vkAcquireNextImageKHR`, `vkAcquireNextImage2KHR`,
`vkQueuePresentKHR`, `vkQueueWaitIdle`, `vkDeviceWaitIdle`,
`vkCreateDescriptorPool`, `vkAllocateDescriptorSets`,
`vkUpdateDescriptorSets`.

All other entry points are forwarded transparently via the real
loader's `vkGetInstanceProcAddr` / `vkGetDeviceProcAddr`.

## Comparing vendor vs manet

```bat
rem capture vendor
adb shell "LD_PRELOAD=/data/local/tmp/libmali_syshook.so MALI_HOOK_LOG=/data/local/tmp/vendor.jsonl cmd gpu vkjson"
adb pull /data/local/tmp/vendor.jsonl

rem bind-mount manet, capture
adb shell "su -c 'mount --bind /data/local/tmp/manet/libvulkan_manet.so /vendor/lib64/hw/vulkan.rk3588.so'; su -c 'stop gpu; start gpu'; sleep 1"
adb shell "LD_PRELOAD=/data/local/tmp/libmali_syshook.so MALI_HOOK_LOG=/data/local/tmp/manet.jsonl cmd gpu vkjson"
adb pull /data/local/tmp/manet.jsonl

rem diff the ioctl sequences
jq -c 'select(.kind=="ioctl_enter"or.kind=="ioctl_exit") | {ts,kind,name,in,out,ret,errno}' vendor.jsonl > vendor_ioctls.jsonl
jq -c 'select(.kind=="ioctl_enter"or.kind=="ioctl_exit") | {ts,kind,name,in,out,ret,errno}' manet.jsonl  > manet_ioctls.jsonl
diff vendor_ioctls.jsonl manet_ioctls.jsonl | less
```

## Known limitations

- Statically-linked libc calls (none in the Android Vulkan stack we
  care about — vendor blobs and the loader use bionic) would bypass
  PLT shadowing.
- The Vulkan trampoline list is a hand-curated subset of high-traffic
  entry points. Calls we don't wrap are still observable as the kbase
  ioctls they generate; if a specific Vk call's args matter, add it
  to `kWrappedFns` in `vk_hook.cpp`.
- The Android HMI offset delta is device/driver-build specific. The
  default `0x731000` was verified against the current RK3588
  `libGLES_mali.so`; override `MALI_HOOK_HMI_SO_DELTA` or regenerate
  labels after changing vendor blobs.
- Per-event buffer is 4 KiB. If you stuff `bytes()` with > 128 byte
  arrays the line is truncated and flagged with `"trunc":1`.
- `munmap` is logged unconditionally because we don't track the
  reverse mapping. Filter by addr-range offline if needed.
- ISA dumps are executable kbase BO snapshots, not Vulkan shader modules.
  They require the BO to be CPU mapped by the vendor driver. The hook dumps
  on `MEM_SYNC`, `CS_QUEUE_KICK`, `KCPU_QUEUE_ENQUEUE`, pipeline creation,
  and `munmap`, with hash de-duplication. When de-duplication suppresses a new
  binary write during pipeline creation, `shader_isa_dump_ref` preserves the
  ISA/SPIR-V mapping for the existing ISA file.
