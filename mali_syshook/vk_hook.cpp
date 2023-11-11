#include "vk_hook.h"
#include "log_jsonl.h"
#include "shader_dump.h"

#include <android/log.h>
#include <dlfcn.h>
#include <mutex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <unordered_map>

#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>

#define TAG "MALI_SYSHOOK"

#if defined(__ANDROID__) && __ANDROID_API__ < 24
extern "C" void *dlvsym(void *handle, const char *symbol,
                        const char *version) __attribute__((weak));
#endif

namespace mali_hook {

namespace {

// Atomics — these are read on every wrapper call from any thread and
// written exactly once (idempotently) by `resolve_real_loader`.
std::atomic<PFN_vkGetInstanceProcAddr> g_real_gipa{nullptr};
std::atomic<PFN_vkGetDeviceProcAddr> g_real_gdpa{nullptr};
using PFN_dlsym = void *(*)(void *, const char *);
std::atomic<PFN_dlsym> g_real_dlsym{nullptr};
std::once_flag g_loader_once;

// Cache real entry points keyed by name so trampolines can find
// their target without re-running GIPA each time.
std::mutex g_proc_mutex;
std::unordered_map<std::string, PFN_vkVoidFunction> g_proc_cache;

void remember_real(const char *name, PFN_vkVoidFunction fn) {
   if (!name || !fn) {
      return;
   }
   std::lock_guard<std::mutex> g(g_proc_mutex);
   g_proc_cache[name] = fn;
}

void *call_real_dlsym(void *handle, const char *name) {
   PFN_dlsym fn = g_real_dlsym.load(std::memory_order_acquire);
   if (!fn) {
      if (&dlvsym) {
         fn = (PFN_dlsym)dlvsym(RTLD_NEXT, "dlsym", "LIBC");
      }
      g_real_dlsym.store(fn, std::memory_order_release);
   }
   return fn ? fn(handle, name) : nullptr;
}

PFN_vkVoidFunction lookup_real(const char *name) {
   {
      std::lock_guard<std::mutex> g(g_proc_mutex);
      auto it = g_proc_cache.find(name);
      if (it != g_proc_cache.end()) {
         return it->second;
      }
   }
   PFN_vkVoidFunction fn = nullptr;
   PFN_vkGetInstanceProcAddr gipa = g_real_gipa.load(std::memory_order_acquire);
   if (gipa) {
      fn = gipa(VK_NULL_HANDLE, name);
   }
   if (!fn) {
      fn = (PFN_vkVoidFunction)call_real_dlsym(RTLD_NEXT, name);
   }
   {
      std::lock_guard<std::mutex> g(g_proc_mutex);
      g_proc_cache[name] = fn;
   }
   return fn;
}

PFN_vkVoidFunction lookup_real_device(VkDevice dev, const char *name) {
   PFN_vkGetDeviceProcAddr gdpa = g_real_gdpa.load(std::memory_order_acquire);
   if (dev && gdpa) {
      PFN_vkVoidFunction fn = gdpa(dev, name);
      if (fn) {
         return fn;
      }
   }
   return lookup_real(name);
}

std::atomic<uint64_t> g_next_frame_number{1};
thread_local uint64_t g_tls_frame_number = 0;

uint64_t current_frame_number() { return g_tls_frame_number; }

uint64_t begin_frame_number() {
   uint64_t frame = g_next_frame_number.fetch_add(1, std::memory_order_relaxed);
   g_tls_frame_number = frame;
   return frame;
}

uint64_t max_frame_count() {
   static uint64_t max_frames = []() -> uint64_t {
      const char *env = getenv("MALI_HOOK_MAX_FRAMES");
      if (!env || !*env) {
         return (uint64_t)0;
      }
      return (uint64_t)strtoull(env, nullptr, 0);
   }();
   return max_frames;
}

uint64_t hmi_so_offset_delta() {
   static uint64_t delta = []() -> uint64_t {
      const char *env = getenv("MALI_HOOK_HMI_SO_DELTA");
      if (!env || !*env) {
         return (uint64_t)0x731000;
      }
      return (uint64_t)strtoull(env, nullptr, 0);
   }();
   return delta;
}

void maybe_stop_after_frame() {
   uint64_t max_frames = max_frame_count();
   uint64_t frame = current_frame_number();
   if (max_frames && frame >= max_frames) {
      LogBuilder("trace_stop").u64("frameNumber", frame).commit();
      _exit(0);
   }
}

bool module_name_contains(const Dl_info &info, const char *needle) {
   return info.dli_fname && needle && strstr(info.dli_fname, needle);
}

void append_proc_location(LogBuilder &b, const char *prefix,
                          PFN_vkVoidFunction fn) {
   if (!fn) {
      return;
   }
   Dl_info info{};
   if (!dladdr((void *)fn, &info) || !info.dli_fbase) {
      return;
   }

   char name[48];
   uintptr_t addr = (uintptr_t)fn;
   uintptr_t base = (uintptr_t)info.dli_fbase;
   snprintf(name, sizeof(name), "%sModule", prefix);
   b.str(name, info.dli_fname ?: "");
   snprintf(name, sizeof(name), "%sModuleBase", prefix);
   b.hex(name, (uint64_t)base);
   snprintf(name, sizeof(name), "%sSoOffset", prefix);
   b.hex(name, (uint64_t)(addr - base));
   snprintf(name, sizeof(name), "%sSymbol", prefix);
   b.str(name, info.dli_sname ?: "");
   if (info.dli_saddr) {
      uintptr_t sym = (uintptr_t)info.dli_saddr;
      snprintf(name, sizeof(name), "%sSymbolOffset", prefix);
      b.hex(name, (uint64_t)(sym - base));
   }
}

void append_driver_offset_hint(LogBuilder &b, PFN_vkVoidFunction real) {
   if (!real) {
      return;
   }
   Dl_info info{};
   if (!dladdr((void *)real, &info) || !info.dli_fbase) {
      return;
   }

   uintptr_t addr = (uintptr_t)real;
   uintptr_t base = (uintptr_t)info.dli_fbase;
   uint64_t so_offset = (uint64_t)(addr - base);
   if (module_name_contains(info, "libvulkan.so")) {
      uint64_t delta = hmi_so_offset_delta();
      if (!delta) {
         return;
      }
      b.str("driverModuleHint", "libGLES_mali.so")
          .hex("driverSoOffset", so_offset + delta)
          .hex("driverOffsetDelta", delta)
          .str("driverOffsetSource", "android_hmi_realSoOffset_plus_delta");
      return;
   }

   if (module_name_contains(info, "libGLES_mali.so") ||
       module_name_contains(info, "vulkan.")) {
      b.hex("driver", (uint64_t)(uintptr_t)real);
      append_proc_location(b, "driver", real);
      b.str("driverOffsetSource", "direct_vendor_procaddr");
   }
}

void log_procaddr(const char *api, const char *name, uint64_t dispatch,
                  PFN_vkVoidFunction real, PFN_vkVoidFunction returned,
                  bool wrapped, uint64_t caller) {
   LogBuilder b("vk_procaddr");
   b.str("api", api)
       .str("name", name ?: "")
       .hex("dispatch", dispatch)
       .hex("real", (uint64_t)(uintptr_t)real);
   append_proc_location(b, "real", real);
   append_driver_offset_hint(b, real);
   b.hex("returned", (uint64_t)(uintptr_t)returned);
   append_proc_location(b, "returned", returned);
   b.boolean("wrapped", wrapped)
       .hex("caller", caller)
       .u64("frameNumber", current_frame_number());
}

void resolve_real_loader() {
   std::call_once(g_loader_once, [] {
      // Try the standard Android Vulkan loader path first; fall
      // back to RTLD_NEXT which catches anything ahead of us in
      // the search order. dlopen + dlsym are internally
      // synchronised by the linker, so this is safe to do once.
      PFN_vkGetInstanceProcAddr gipa = nullptr;
      PFN_vkGetDeviceProcAddr gdpa = nullptr;
      void *vk = dlopen("libvulkan.so", RTLD_NOW);
      if (vk) {
         gipa = (PFN_vkGetInstanceProcAddr)call_real_dlsym(
             vk, "vkGetInstanceProcAddr");
         gdpa = (PFN_vkGetDeviceProcAddr)call_real_dlsym(
             vk, "vkGetDeviceProcAddr");
      }
      if (!gipa) {
         gipa = (PFN_vkGetInstanceProcAddr)call_real_dlsym(
             RTLD_NEXT, "vkGetInstanceProcAddr");
      }
      if (!gdpa) {
         gdpa = (PFN_vkGetDeviceProcAddr)call_real_dlsym(
             RTLD_NEXT, "vkGetDeviceProcAddr");
      }
      g_real_gipa.store(gipa, std::memory_order_release);
      g_real_gdpa.store(gdpa, std::memory_order_release);
      __android_log_print(ANDROID_LOG_INFO, TAG,
                          "vk_hook: real gipa=%p gdpa=%p",
                          (void *)gipa, (void *)gdpa);
   });
}

// ---------------------------------------------------------------------------
// Argument decoders. Each helper appends a few characteristic fields
// from the input pointer. They are intentionally shallow — pull out
// only what helps cross-driver diff.
// ---------------------------------------------------------------------------

void dump_instance_create_info(LogBuilder &b, const VkInstanceCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo");
   b.hex("flags", ci->flags);
   if (ci->pApplicationInfo) {
      b.obj_begin("app")
          .str("name", ci->pApplicationInfo->pApplicationName ?: "")
          .u64("appVer", ci->pApplicationInfo->applicationVersion)
          .str("engine", ci->pApplicationInfo->pEngineName ?: "")
          .u64("engineVer", ci->pApplicationInfo->engineVersion)
          .hex("apiVer", ci->pApplicationInfo->apiVersion)
          .obj_end();
   }
   b.u64("enabledLayerCount", ci->enabledLayerCount);
   b.u64("enabledExtensionCount", ci->enabledExtensionCount);
   b.obj_end();
}

void dump_device_create_info(LogBuilder &b, const VkDeviceCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo");
   b.hex("flags", ci->flags);
   b.u64("queueCreateInfoCount", ci->queueCreateInfoCount);
   b.u64("enabledExtensionCount", ci->enabledExtensionCount);
   b.obj_end();
}

void dump_buffer_create_info(LogBuilder &b, const VkBufferCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .u64("size", ci->size)
       .hex("usage", ci->usage)
       .hex("flags", ci->flags)
       .u64("sharingMode", ci->sharingMode)
       .obj_end();
}

void dump_image_create_info(LogBuilder &b, const VkImageCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .u64("imageType", ci->imageType)
       .u64("format", ci->format)
       .u64("width", ci->extent.width)
       .u64("height", ci->extent.height)
       .u64("depth", ci->extent.depth)
       .u64("mipLevels", ci->mipLevels)
       .u64("arrayLayers", ci->arrayLayers)
       .u64("samples", ci->samples)
       .u64("tiling", ci->tiling)
       .hex("usage", ci->usage)
       .hex("flags", ci->flags)
       .obj_end();
}

void dump_image_view_create_info(LogBuilder &b,
                                 const VkImageViewCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .hex("image", (uint64_t)(uintptr_t)ci->image)
       .u64("viewType", ci->viewType)
       .u64("format", ci->format)
       .hex("aspectMask", ci->subresourceRange.aspectMask)
       .u64("baseMipLevel", ci->subresourceRange.baseMipLevel)
       .u64("levelCount", ci->subresourceRange.levelCount)
       .u64("baseArrayLayer", ci->subresourceRange.baseArrayLayer)
       .u64("layerCount", ci->subresourceRange.layerCount)
       .obj_end();
}

void dump_memory_allocate_info(LogBuilder &b,
                               const VkMemoryAllocateInfo *info) {
   if (!info) {
      return;
   }
   b.obj_begin("allocInfo")
       .u64("size", info->allocationSize)
       .u64("memoryTypeIndex", info->memoryTypeIndex)
       .obj_end();
}

void dump_command_pool_create_info(LogBuilder &b,
                                   const VkCommandPoolCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .u64("queueFamilyIndex", ci->queueFamilyIndex)
       .obj_end();
}

void dump_cmdbuf_alloc_info(LogBuilder &b,
                            const VkCommandBufferAllocateInfo *info) {
   if (!info) {
      return;
   }
   b.obj_begin("allocInfo")
       .hex("commandPool", (uint64_t)(uintptr_t)info->commandPool)
       .u64("level", info->level)
       .u64("commandBufferCount", info->commandBufferCount)
       .obj_end();
}

void dump_descriptor_pool_create_info(LogBuilder &b,
                                      const VkDescriptorPoolCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .u64("maxSets", ci->maxSets)
       .u64("poolSizeCount", ci->poolSizeCount)
       .obj_end();
}

void dump_descriptor_set_alloc_info(LogBuilder &b,
                                    const VkDescriptorSetAllocateInfo *info) {
   if (!info) {
      return;
   }
   b.obj_begin("allocInfo")
       .hex("descriptorPool", (uint64_t)(uintptr_t)info->descriptorPool)
       .u64("descriptorSetCount", info->descriptorSetCount)
       .obj_end();
}

void dump_descriptor_set_layout_create_info(
    LogBuilder &b, const VkDescriptorSetLayoutCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .u64("bindingCount", ci->bindingCount)
       .obj_end();
}

void dump_pipeline_layout_create_info(LogBuilder &b,
                                      const VkPipelineLayoutCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .u64("setLayoutCount", ci->setLayoutCount)
       .u64("pushConstantRangeCount", ci->pushConstantRangeCount)
       .obj_end();
}

void dump_render_pass_create_info(LogBuilder &b,
                                  const VkRenderPassCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .u64("attachmentCount", ci->attachmentCount)
       .u64("subpassCount", ci->subpassCount)
       .u64("dependencyCount", ci->dependencyCount)
       .obj_end();
}

void dump_framebuffer_create_info(LogBuilder &b,
                                  const VkFramebufferCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .hex("renderPass", (uint64_t)(uintptr_t)ci->renderPass)
       .u64("attachmentCount", ci->attachmentCount)
       .u64("width", ci->width)
       .u64("height", ci->height)
       .u64("layers", ci->layers)
       .obj_end();
}

void dump_shader_module_create_info(LogBuilder &b,
                                    const VkShaderModuleCreateInfo *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .u64("codeSize", ci->codeSize)
       .u64("codeWords", ci->codeSize / 4)
       .obj_end();
}

void dump_compute_pipeline_create_info(
    LogBuilder &b, const VkComputePipelineCreateInfo *ci, uint32_t i) {
   if (!ci) {
      return;
   }
   b.obj_begin(i == 0 ? "createInfo" : "createInfo_n")
       .hex("flags", ci->flags)
       .u64("stage", ci->stage.stage)
       .str("entryName", ci->stage.pName ?: "")
       .hex("module", (uint64_t)(uintptr_t)ci->stage.module)
       .hex("layout", (uint64_t)(uintptr_t)ci->layout)
       .obj_end();
}

void dump_graphics_pipeline_create_info(
    LogBuilder &b, const VkGraphicsPipelineCreateInfo *ci, uint32_t i) {
   if (!ci) {
      return;
   }
   b.obj_begin(i == 0 ? "createInfo" : "createInfo_n")
       .hex("flags", ci->flags)
       .u64("stageCount", ci->stageCount)
       .hex("layout", (uint64_t)(uintptr_t)ci->layout)
       .hex("renderPass", (uint64_t)(uintptr_t)ci->renderPass)
       .u64("subpass", ci->subpass)
       .hex("basePipelineHandle",
            (uint64_t)(uintptr_t)ci->basePipelineHandle)
       .i64("basePipelineIndex", ci->basePipelineIndex)
       .obj_end();
}

void dump_swapchain_create_info(LogBuilder &b,
                                const VkSwapchainCreateInfoKHR *ci) {
   if (!ci) {
      return;
   }
   b.obj_begin("createInfo")
       .hex("flags", ci->flags)
       .hex("surface", (uint64_t)(uintptr_t)ci->surface)
       .u64("minImageCount", ci->minImageCount)
       .u64("imageFormat", ci->imageFormat)
       .u64("imageColorSpace", ci->imageColorSpace)
       .u64("width", ci->imageExtent.width)
       .u64("height", ci->imageExtent.height)
       .u64("imageArrayLayers", ci->imageArrayLayers)
       .hex("imageUsage", ci->imageUsage)
       .u64("presentMode", ci->presentMode)
       .hex("oldSwapchain", (uint64_t)(uintptr_t)ci->oldSwapchain)
       .obj_end();
}

void dump_submit_info(LogBuilder &b, const VkSubmitInfo *si) {
   if (!si) {
      return;
   }
   b.obj_begin("submit")
       .u64("waitSemaphoreCount", si->waitSemaphoreCount)
       .u64("commandBufferCount", si->commandBufferCount)
       .u64("signalSemaphoreCount", si->signalSemaphoreCount)
       .obj_end();
}

void dump_present_info(LogBuilder &b, const VkPresentInfoKHR *pi) {
   if (!pi) {
      return;
   }
   b.obj_begin("present")
       .u64("waitSemaphoreCount", pi->waitSemaphoreCount)
       .u64("swapchainCount", pi->swapchainCount)
       .obj_end();
}

void dump_acquire_info(LogBuilder &b, const VkAcquireNextImageInfoKHR *info) {
   if (!info) {
      return;
   }
   b.obj_begin("acquire")
       .hex("swapchain", (uint64_t)(uintptr_t)info->swapchain)
       .u64("timeout", info->timeout)
       .hex("semaphore", (uint64_t)(uintptr_t)info->semaphore)
       .hex("fence", (uint64_t)(uintptr_t)info->fence)
       .u64("deviceMask", info->deviceMask)
       .obj_end();
}

void dump_buffer_image_copy(LogBuilder &b, const VkBufferImageCopy *region,
                            uint32_t i) {
   if (!region) {
      return;
   }
   b.obj_begin(i == 0 ? "region" : "region_n")
       .u64("bufferOffset", region->bufferOffset)
       .u64("bufferRowLength", region->bufferRowLength)
       .u64("bufferImageHeight", region->bufferImageHeight)
       .hex("aspectMask", region->imageSubresource.aspectMask)
       .u64("mipLevel", region->imageSubresource.mipLevel)
       .u64("baseArrayLayer", region->imageSubresource.baseArrayLayer)
       .u64("layerCount", region->imageSubresource.layerCount)
       .i64("imageOffsetX", region->imageOffset.x)
       .i64("imageOffsetY", region->imageOffset.y)
       .i64("imageOffsetZ", region->imageOffset.z)
       .u64("width", region->imageExtent.width)
       .u64("height", region->imageExtent.height)
       .u64("depth", region->imageExtent.depth)
       .obj_end();
}

void dump_image_copy(LogBuilder &b, const VkImageCopy *region, uint32_t i) {
   if (!region) {
      return;
   }
   b.obj_begin(i == 0 ? "region" : "region_n")
       .hex("srcAspectMask", region->srcSubresource.aspectMask)
       .u64("srcMipLevel", region->srcSubresource.mipLevel)
       .u64("srcBaseArrayLayer", region->srcSubresource.baseArrayLayer)
       .u64("srcLayerCount", region->srcSubresource.layerCount)
       .i64("srcOffsetX", region->srcOffset.x)
       .i64("srcOffsetY", region->srcOffset.y)
       .i64("srcOffsetZ", region->srcOffset.z)
       .hex("dstAspectMask", region->dstSubresource.aspectMask)
       .u64("dstMipLevel", region->dstSubresource.mipLevel)
       .u64("dstBaseArrayLayer", region->dstSubresource.baseArrayLayer)
       .u64("dstLayerCount", region->dstSubresource.layerCount)
       .i64("dstOffsetX", region->dstOffset.x)
       .i64("dstOffsetY", region->dstOffset.y)
       .i64("dstOffsetZ", region->dstOffset.z)
       .u64("width", region->extent.width)
       .u64("height", region->extent.height)
       .u64("depth", region->extent.depth)
       .obj_end();
}

void dump_image_memory_barrier(LogBuilder &b,
                               const VkImageMemoryBarrier *barrier,
                               uint32_t i) {
   if (!barrier) {
      return;
   }
   b.obj_begin(i == 0 ? "imageBarrier" : "imageBarrier_n")
       .hex("srcAccessMask", barrier->srcAccessMask)
       .hex("dstAccessMask", barrier->dstAccessMask)
       .u64("oldLayout", barrier->oldLayout)
       .u64("newLayout", barrier->newLayout)
       .u64("srcQueueFamilyIndex", barrier->srcQueueFamilyIndex)
       .u64("dstQueueFamilyIndex", barrier->dstQueueFamilyIndex)
       .hex("image", (uint64_t)(uintptr_t)barrier->image)
       .hex("aspectMask", barrier->subresourceRange.aspectMask)
       .u64("baseMipLevel", barrier->subresourceRange.baseMipLevel)
       .u64("levelCount", barrier->subresourceRange.levelCount)
       .u64("baseArrayLayer", barrier->subresourceRange.baseArrayLayer)
       .u64("layerCount", barrier->subresourceRange.layerCount)
       .obj_end();
}

void dump_mapped_memory_range(LogBuilder &b, const VkMappedMemoryRange *range,
                              uint32_t i) {
   if (!range) {
      return;
   }
   b.obj_begin(i == 0 ? "range" : "range_n")
       .hex("memory", (uint64_t)(uintptr_t)range->memory)
       .u64("offset", range->offset)
       .u64("size", range->size)
       .obj_end();
}

struct SpirvDump {
   uint64_t module = 0;
   uint64_t hash = 0;
   size_t bytes = 0;
   char path[768] = {};
};

std::mutex g_spirv_mutex;
std::unordered_map<uint64_t, SpirvDump> g_spirv_by_module;

std::string hex_json(uint64_t v) {
   char buf[32];
   snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
   return std::string(buf);
}

std::string json_escape(const char *s) {
   std::string out;
   out.push_back('"');
   if (s) {
      for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
         switch (*p) {
         case '\\': out += "\\\\"; break;
         case '"': out += "\\\""; break;
         case '\b': out += "\\b"; break;
         case '\f': out += "\\f"; break;
         case '\n': out += "\\n"; break;
         case '\r': out += "\\r"; break;
         case '\t': out += "\\t"; break;
         default:
            if (*p < 0x20) {
               char buf[8];
               snprintf(buf, sizeof(buf), "\\u%04x", *p);
               out += buf;
            } else {
               out.push_back((char)*p);
            }
            break;
         }
      }
   }
   out.push_back('"');
   return out;
}

bool write_binary_file(const char *path, const void *data, size_t bytes) {
   FILE *f = fopen(path, "wb");
   if (!f) {
      return false;
   }
   bool ok = fwrite(data, 1, bytes, f) == bytes;
   fclose(f);
   return ok;
}

bool record_spirv_module(VkShaderModule module,
                         const VkShaderModuleCreateInfo *ci,
                         SpirvDump *out_info) {
   if (!shader_dump_enabled() || !module || !ci || !ci->pCode ||
       !ci->codeSize) {
      return false;
   }

   SpirvDump info;
   info.module = (uint64_t)(uintptr_t)module;
   info.bytes = ci->codeSize;
   info.hash = shader_dump_hash64(ci->pCode, ci->codeSize);
   snprintf(info.path, sizeof(info.path),
            "%s/spirv_module_%llx_%zu_%016llx.spv",
            shader_dump_output_dir(), (unsigned long long)info.module,
            info.bytes, (unsigned long long)info.hash);

   if (!write_binary_file(info.path, ci->pCode, ci->codeSize)) {
      LogBuilder("shader_spirv_dump_error")
          .hex("module", info.module)
          .str("path", info.path)
          .u64("bytes", info.bytes)
          .hex("hash", info.hash);
      return false;
   }

   {
      std::lock_guard<std::mutex> g(g_spirv_mutex);
      g_spirv_by_module[info.module] = info;
   }

   LogBuilder("shader_spirv_dump")
       .hex("module", info.module)
       .str("path", info.path)
       .u64("bytes", info.bytes)
       .hex("hash", info.hash);
   if (out_info) {
      *out_info = info;
   }
   return true;
}

bool lookup_spirv_module(VkShaderModule module, SpirvDump *out_info) {
   uint64_t key = (uint64_t)(uintptr_t)module;
   std::lock_guard<std::mutex> g(g_spirv_mutex);
   auto it = g_spirv_by_module.find(key);
   if (it == g_spirv_by_module.end()) {
      return false;
   }
   if (out_info) {
      *out_info = it->second;
   }
   return true;
}

std::string stage_context_json(VkShaderStageFlagBits stage, const char *entry,
                               VkShaderModule module) {
   std::string s = "{";
   uint64_t module_key = (uint64_t)(uintptr_t)module;
   s += "\"stage\":" + std::to_string((uint32_t)stage);
   s += ",\"entry\":" + json_escape(entry ? entry : "");
   s += ",\"module\":\"" + hex_json(module_key) + "\"";
   SpirvDump spv;
   if (lookup_spirv_module(module, &spv)) {
      s += ",\"spirvPath\":" + json_escape(spv.path);
      s += ",\"spirvHash\":\"" + hex_json(spv.hash) + "\"";
      s += ",\"spirvBytes\":" + std::to_string(spv.bytes);
   } else {
      s += ",\"spirvMissing\":true";
   }
   s += "}";
   return s;
}

std::string compute_pipeline_context(uint32_t createInfoCount,
                                     const VkComputePipelineCreateInfo *infos) {
   std::string s = "{\"pipeline\":\"compute\",\"createInfoCount\":";
   s += std::to_string(createInfoCount);
   s += ",\"stages\":[";
   uint32_t limit = createInfoCount > 16 ? 16 : createInfoCount;
   for (uint32_t i = 0; infos && i < limit; ++i) {
      if (i) {
         s += ",";
      }
      std::string st = stage_context_json(
          infos[i].stage.stage, infos[i].stage.pName, infos[i].stage.module);
      st.insert(1, "\"pipelineIndex\":" + std::to_string(i) + ",");
      s += st;
   }
   s += "]";
   if (createInfoCount > limit) {
      s += ",\"truncated\":true";
   }
   s += "}";
   return s;
}

std::string graphics_pipeline_context(
    uint32_t createInfoCount, const VkGraphicsPipelineCreateInfo *infos) {
   std::string s = "{\"pipeline\":\"graphics\",\"createInfoCount\":";
   s += std::to_string(createInfoCount);
   s += ",\"stages\":[";
   uint32_t emitted = 0;
   bool truncated = false;
   for (uint32_t i = 0; infos && i < createInfoCount; ++i) {
      for (uint32_t j = 0; j < infos[i].stageCount; ++j) {
         if (emitted >= 32) {
            truncated = true;
            break;
         }
         if (emitted) {
            s += ",";
         }
         const VkPipelineShaderStageCreateInfo &stage = infos[i].pStages[j];
         std::string st =
             stage_context_json(stage.stage, stage.pName, stage.module);
         st.insert(1, "\"stageIndex\":" + std::to_string(j) + ",");
         st.insert(1, "\"pipelineIndex\":" + std::to_string(i) + ",");
         s += st;
         emitted++;
      }
      if (truncated) {
         break;
      }
   }
   s += "]";
   if (truncated) {
      s += ",\"truncated\":true";
   }
   s += "}";
   return s;
}

void log_pipeline_spirv_map(const char *fn, VkResult result,
                            const char *context_json) {
   LogBuilder ev("shader_isa_spirv_map");
   ev.str("fn", fn ? fn : "").i64("result", (int64_t)result);
   if (context_json && *context_json) {
      ev.raw("spirvContext", context_json);
   }
}

void append_isa_relation_fields(LogBuilder &ev,
                                const ShaderIsaDumpInfo &isa) {
   ev.str("isaPath", isa.path)
       .hex("isaGpuVa", isa.gpu_va)
       .hex("isaFlags", isa.flags)
       .hex("isaCpu", isa.cpu)
       .u64("isaBytes", isa.bytes)
       .u64("isaAllocSize", isa.alloc_size)
       .hex("isaHash", isa.hash)
       .u64("isaSeq", isa.seq);
}

void append_stage_relation_fields(LogBuilder &ev, uint32_t pipeline_index,
                                  uint32_t stage_index,
                                  VkShaderStageFlagBits stage,
                                  const char *entry,
                                  VkShaderModule module) {
   ev.u64("pipelineIndex", pipeline_index)
       .u64("stageIndex", stage_index)
       .u64("stage", (uint32_t)stage)
       .str("entry", entry ? entry : "")
       .hex("module", (uint64_t)(uintptr_t)module);
   SpirvDump spv;
   if (lookup_spirv_module(module, &spv)) {
      ev.str("spirvPath", spv.path)
          .u64("spirvBytes", spv.bytes)
          .hex("spirvHash", spv.hash);
   } else {
      ev.boolean("spirvMissing", true);
   }
}

void log_isa_spirv_table_summary(const char *fn, const char *pipeline,
                                 VkResult result, size_t isa_total,
                                 size_t isa_copied, uint32_t stage_total,
                                 uint32_t stage_emitted) {
   LogBuilder("shader_isa_spirv_table")
       .str("fn", fn ? fn : "")
       .str("pipeline", pipeline ? pipeline : "")
       .i64("result", (int64_t)result)
       .u64("isaCount", isa_total)
       .u64("isaEmitted", isa_copied)
       .boolean("isaTruncated", isa_total > isa_copied)
       .u64("stageCount", stage_total)
       .u64("stageEmitted", stage_emitted)
       .boolean("stageTruncated", stage_total > stage_emitted)
       .u64("rowCount", isa_copied * stage_emitted)
       .str("rowKind", "shader_isa_spirv_relation");
}

void log_compute_isa_spirv_table(
    const char *fn, VkResult result, uint32_t createInfoCount,
    const VkComputePipelineCreateInfo *infos) {
   ShaderIsaDumpInfo isas[128];
   size_t isa_total = shader_dump_collect_infos(isas, 128);
   size_t isa_copied = isa_total < 128 ? isa_total : 128;
   uint32_t stage_total = infos ? createInfoCount : 0;
   uint32_t stage_emitted = stage_total > 16 ? 16 : stage_total;
   log_isa_spirv_table_summary(fn, "compute", result, isa_total, isa_copied,
                               stage_total, stage_emitted);

   uint64_t row_index = 0;
   for (uint32_t i = 0; infos && i < stage_emitted; ++i) {
      for (size_t isa_i = 0; isa_i < isa_copied; ++isa_i) {
         LogBuilder ev("shader_isa_spirv_relation");
         ev.str("fn", fn ? fn : "")
             .str("pipeline", "compute")
             .i64("result", (int64_t)result)
             .u64("rowIndex", row_index++)
             .u64("isaIndex", isa_i)
             .u64("stageTableIndex", i);
         append_isa_relation_fields(ev, isas[isa_i]);
         append_stage_relation_fields(ev, i, 0, infos[i].stage.stage,
                                      infos[i].stage.pName,
                                      infos[i].stage.module);
      }
   }
}

uint32_t graphics_stage_total(uint32_t createInfoCount,
                              const VkGraphicsPipelineCreateInfo *infos) {
   uint32_t total = 0;
   for (uint32_t i = 0; infos && i < createInfoCount; ++i) {
      if (infos[i].pStages) {
         total += infos[i].stageCount;
      }
   }
   return total;
}

void log_graphics_isa_spirv_table(
    const char *fn, VkResult result, uint32_t createInfoCount,
    const VkGraphicsPipelineCreateInfo *infos) {
   ShaderIsaDumpInfo isas[128];
   size_t isa_total = shader_dump_collect_infos(isas, 128);
   size_t isa_copied = isa_total < 128 ? isa_total : 128;
   uint32_t stage_total = graphics_stage_total(createInfoCount, infos);
   uint32_t stage_emitted = stage_total > 32 ? 32 : stage_total;
   log_isa_spirv_table_summary(fn, "graphics", result, isa_total, isa_copied,
                               stage_total, stage_emitted);

   uint32_t emitted = 0;
   uint64_t row_index = 0;
   for (uint32_t i = 0; infos && i < createInfoCount; ++i) {
      if (!infos[i].pStages) {
         continue;
      }
      for (uint32_t j = 0; j < infos[i].stageCount; ++j) {
         if (emitted >= stage_emitted) {
            return;
         }
         const VkPipelineShaderStageCreateInfo &stage = infos[i].pStages[j];
         for (size_t isa_i = 0; isa_i < isa_copied; ++isa_i) {
            LogBuilder ev("shader_isa_spirv_relation");
            ev.str("fn", fn ? fn : "")
                .str("pipeline", "graphics")
                .i64("result", (int64_t)result)
                .u64("rowIndex", row_index++)
                .u64("isaIndex", isa_i)
                .u64("stageTableIndex", emitted);
            append_isa_relation_fields(ev, isas[isa_i]);
            append_stage_relation_fields(ev, i, j, stage.stage, stage.pName,
                                         stage.module);
         }
         emitted++;
      }
   }
}

// ---------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------

// Stamp every vk_enter with the address of the real entry point we
// dispatched to (from the vendor ICD or system loader). Static
// analysis tooling — IDA / Ghidra / objdump — can then map the
// trace back to disassembled functions in the actual driver
// binary. We also include the return address so the call site in
// the app/loader is visible.
static inline uint64_t real_addr(const char *name) {
   PFN_vkVoidFunction p = mali_hook::lookup_real(name);
   return (uint64_t)(uintptr_t)p;
}

#define VK_TRAMP_BEGIN(NAME)                                                    \
   uint64_t __ret_addr =                                                        \
       (uint64_t)(uintptr_t)__builtin_return_address(0);                        \
   uint64_t __real_addr = real_addr(NAME);                                      \
   LogBuilder __ev_in("vk_enter");                                              \
   __ev_in.str("fn", NAME);                                                     \
   __ev_in.hex("real", __real_addr);                                            \
   __ev_in.hex("caller", __ret_addr);                                           \
   __ev_in.u64("frameNumber", current_frame_number());
#define VK_TRAMP_EXIT(NAME, RESULT)                                             \
   LogBuilder __ev_out("vk_exit");                                              \
   __ev_out.str("fn", NAME).hex("real", __real_addr)                            \
       .i64("result", (int64_t)(RESULT))                                        \
       .u64("frameNumber", current_frame_number());

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateInstance(
    const VkInstanceCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkInstance *pInstance) {
   VK_TRAMP_BEGIN("vkCreateInstance")
   dump_instance_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateInstance)lookup_real("vkCreateInstance");
   VkResult r = real ? real(pCreateInfo, pAllocator, pInstance)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateInstance", r)
   if (r == VK_SUCCESS && pInstance) {
      __ev_out.hex("instance", (uint64_t)(uintptr_t)*pInstance);
   }
   return r;
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkDestroyInstance(
    VkInstance instance, const VkAllocationCallbacks *pAllocator) {
   auto real = (PFN_vkDestroyInstance)lookup_real("vkDestroyInstance");
   LogBuilder __ev("vk_enter");
   __ev.str("fn", "vkDestroyInstance")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("instance", (uint64_t)(uintptr_t)instance);
   __ev.commit();
   if (real) {
      real(instance, pAllocator);
   }
   LogBuilder __ev2("vk_exit");
   __ev2.str("fn", "vkDestroyInstance")
       .u64("frameNumber", current_frame_number());
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkEnumeratePhysicalDevices(
    VkInstance instance, uint32_t *pPhysicalDeviceCount,
    VkPhysicalDevice *pPhysicalDevices) {
   VK_TRAMP_BEGIN("vkEnumeratePhysicalDevices")
   __ev_in.hex("instance", (uint64_t)(uintptr_t)instance);
   __ev_in.commit();
   auto real = (PFN_vkEnumeratePhysicalDevices)lookup_real(
       "vkEnumeratePhysicalDevices");
   VkResult r =
       real ? real(instance, pPhysicalDeviceCount, pPhysicalDevices)
            : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkEnumeratePhysicalDevices", r)
   if (pPhysicalDeviceCount) {
      __ev_out.u64("count", *pPhysicalDeviceCount);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateDevice(
    VkPhysicalDevice physicalDevice, const VkDeviceCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkDevice *pDevice) {
   VK_TRAMP_BEGIN("vkCreateDevice")
   __ev_in.hex("physicalDevice", (uint64_t)(uintptr_t)physicalDevice);
   dump_device_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateDevice)lookup_real("vkCreateDevice");
   VkResult r = real ? real(physicalDevice, pCreateInfo, pAllocator, pDevice)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateDevice", r)
   if (r == VK_SUCCESS && pDevice) {
      __ev_out.hex("device", (uint64_t)(uintptr_t)*pDevice);
   }
   return r;
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkDestroyDevice(
    VkDevice device, const VkAllocationCallbacks *pAllocator) {
   auto real = (PFN_vkDestroyDevice)lookup_real_device(device, "vkDestroyDevice");
   LogBuilder __ev("vk_enter");
   __ev.str("fn", "vkDestroyDevice")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("device", (uint64_t)(uintptr_t)device);
   __ev.commit();
   if (real) {
      real(device, pAllocator);
   }
   LogBuilder("vk_exit")
       .str("fn", "vkDestroyDevice")
       .u64("frameNumber", current_frame_number());
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkAllocateMemory(
    VkDevice device, const VkMemoryAllocateInfo *pAllocateInfo,
    const VkAllocationCallbacks *pAllocator, VkDeviceMemory *pMemory) {
   VK_TRAMP_BEGIN("vkAllocateMemory")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_memory_allocate_info(__ev_in, pAllocateInfo);
   __ev_in.commit();
   auto real = (PFN_vkAllocateMemory)lookup_real_device(device,
                                                       "vkAllocateMemory");
   VkResult r = real ? real(device, pAllocateInfo, pAllocator, pMemory)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkAllocateMemory", r)
   if (r == VK_SUCCESS && pMemory) {
      __ev_out.hex("memory", (uint64_t)(uintptr_t)*pMemory);
   }
   return r;
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkFreeMemory(
    VkDevice device, VkDeviceMemory memory,
    const VkAllocationCallbacks *pAllocator) {
   auto real = (PFN_vkFreeMemory)lookup_real_device(device, "vkFreeMemory");
   LogBuilder __ev("vk_enter");
   __ev.str("fn", "vkFreeMemory")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("device", (uint64_t)(uintptr_t)device)
       .hex("memory", (uint64_t)(uintptr_t)memory);
   __ev.commit();
   if (real) {
      real(device, memory, pAllocator);
   }
   LogBuilder("vk_exit")
       .str("fn", "vkFreeMemory")
       .u64("frameNumber", current_frame_number());
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkMapMemory(
    VkDevice device, VkDeviceMemory memory, VkDeviceSize offset,
    VkDeviceSize size, VkMemoryMapFlags flags, void **ppData) {
   VK_TRAMP_BEGIN("vkMapMemory")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device)
       .hex("memory", (uint64_t)(uintptr_t)memory)
       .u64("offset", offset)
       .u64("size", size)
       .hex("flags", flags);
   __ev_in.commit();
   auto real = (PFN_vkMapMemory)lookup_real_device(device, "vkMapMemory");
   VkResult r = real ? real(device, memory, offset, size, flags, ppData)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkMapMemory", r)
   if (r == VK_SUCCESS && ppData) {
      __ev_out.hex("ptr", (uint64_t)(uintptr_t)*ppData);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkFlushMappedMemoryRanges(
    VkDevice device, uint32_t memoryRangeCount,
    const VkMappedMemoryRange *pMemoryRanges) {
   VK_TRAMP_BEGIN("vkFlushMappedMemoryRanges")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device)
       .u64("rangeCount", memoryRangeCount);
   if (pMemoryRanges && memoryRangeCount > 0) {
      dump_mapped_memory_range(__ev_in, &pMemoryRanges[0], 0);
   }
   __ev_in.commit();
   auto real = (PFN_vkFlushMappedMemoryRanges)lookup_real_device(
       device, "vkFlushMappedMemoryRanges");
   VkResult r = real ? real(device, memoryRangeCount, pMemoryRanges)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkFlushMappedMemoryRanges", r)
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkBindBufferMemory(
    VkDevice device, VkBuffer buffer, VkDeviceMemory memory,
    VkDeviceSize memoryOffset) {
   VK_TRAMP_BEGIN("vkBindBufferMemory")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device)
       .hex("buffer", (uint64_t)(uintptr_t)buffer)
       .hex("memory", (uint64_t)(uintptr_t)memory)
       .u64("offset", memoryOffset);
   __ev_in.commit();
   auto real = (PFN_vkBindBufferMemory)lookup_real_device(
       device, "vkBindBufferMemory");
   VkResult r = real ? real(device, buffer, memory, memoryOffset)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkBindBufferMemory", r)
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkBindImageMemory(
    VkDevice device, VkImage image, VkDeviceMemory memory,
    VkDeviceSize memoryOffset) {
   VK_TRAMP_BEGIN("vkBindImageMemory")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device)
       .hex("image", (uint64_t)(uintptr_t)image)
       .hex("memory", (uint64_t)(uintptr_t)memory)
       .u64("offset", memoryOffset);
   __ev_in.commit();
   auto real =
       (PFN_vkBindImageMemory)lookup_real_device(device, "vkBindImageMemory");
   VkResult r = real ? real(device, image, memory, memoryOffset)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkBindImageMemory", r)
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateBuffer(
    VkDevice device, const VkBufferCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkBuffer *pBuffer) {
   VK_TRAMP_BEGIN("vkCreateBuffer")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_buffer_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateBuffer)lookup_real_device(device, "vkCreateBuffer");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pBuffer)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateBuffer", r)
   if (r == VK_SUCCESS && pBuffer) {
      __ev_out.hex("buffer", (uint64_t)(uintptr_t)*pBuffer);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateImage(
    VkDevice device, const VkImageCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkImage *pImage) {
   VK_TRAMP_BEGIN("vkCreateImage")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_image_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateImage)lookup_real_device(device, "vkCreateImage");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pImage)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateImage", r)
   if (r == VK_SUCCESS && pImage) {
      __ev_out.hex("image", (uint64_t)(uintptr_t)*pImage);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateImageView(
    VkDevice device, const VkImageViewCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkImageView *pView) {
   VK_TRAMP_BEGIN("vkCreateImageView")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_image_view_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real =
       (PFN_vkCreateImageView)lookup_real_device(device, "vkCreateImageView");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pView)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateImageView", r)
   if (r == VK_SUCCESS && pView) {
      __ev_out.hex("imageView", (uint64_t)(uintptr_t)*pView);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateShaderModule(
    VkDevice device, const VkShaderModuleCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkShaderModule *pShaderModule) {
   VK_TRAMP_BEGIN("vkCreateShaderModule")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_shader_module_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateShaderModule)lookup_real_device(
       device, "vkCreateShaderModule");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pShaderModule)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateShaderModule", r)
   if (r == VK_SUCCESS && pShaderModule) {
      __ev_out.hex("module", (uint64_t)(uintptr_t)*pShaderModule);
      SpirvDump spv;
      if (record_spirv_module(*pShaderModule, pCreateInfo, &spv)) {
         __ev_out.str("spirvPath", spv.path)
             .u64("spirvBytes", spv.bytes)
             .hex("spirvHash", spv.hash);
      }
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateDescriptorSetLayout(
    VkDevice device, const VkDescriptorSetLayoutCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator,
    VkDescriptorSetLayout *pSetLayout) {
   VK_TRAMP_BEGIN("vkCreateDescriptorSetLayout")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_descriptor_set_layout_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateDescriptorSetLayout)lookup_real_device(
       device, "vkCreateDescriptorSetLayout");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pSetLayout)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateDescriptorSetLayout", r)
   if (r == VK_SUCCESS && pSetLayout) {
      __ev_out.hex("setLayout", (uint64_t)(uintptr_t)*pSetLayout);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreatePipelineLayout(
    VkDevice device, const VkPipelineLayoutCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkPipelineLayout *pLayout) {
   VK_TRAMP_BEGIN("vkCreatePipelineLayout")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_pipeline_layout_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreatePipelineLayout)lookup_real_device(
       device, "vkCreatePipelineLayout");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pLayout)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreatePipelineLayout", r)
   if (r == VK_SUCCESS && pLayout) {
      __ev_out.hex("layout", (uint64_t)(uintptr_t)*pLayout);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateRenderPass(
    VkDevice device, const VkRenderPassCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkRenderPass *pRenderPass) {
   VK_TRAMP_BEGIN("vkCreateRenderPass")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_render_pass_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real =
       (PFN_vkCreateRenderPass)lookup_real_device(device, "vkCreateRenderPass");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pRenderPass)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateRenderPass", r)
   if (r == VK_SUCCESS && pRenderPass) {
      __ev_out.hex("renderPass", (uint64_t)(uintptr_t)*pRenderPass);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateFramebuffer(
    VkDevice device, const VkFramebufferCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkFramebuffer *pFramebuffer) {
   VK_TRAMP_BEGIN("vkCreateFramebuffer")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_framebuffer_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateFramebuffer)lookup_real_device(
       device, "vkCreateFramebuffer");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pFramebuffer)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateFramebuffer", r)
   if (r == VK_SUCCESS && pFramebuffer) {
      __ev_out.hex("framebuffer", (uint64_t)(uintptr_t)*pFramebuffer);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateComputePipelines(
    VkDevice device, VkPipelineCache pipelineCache, uint32_t createInfoCount,
    const VkComputePipelineCreateInfo *pCreateInfos,
    const VkAllocationCallbacks *pAllocator, VkPipeline *pPipelines) {
   VK_TRAMP_BEGIN("vkCreateComputePipelines")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device)
       .u64("count", createInfoCount);
   if (pCreateInfos && createInfoCount > 0) {
      dump_compute_pipeline_create_info(__ev_in, &pCreateInfos[0], 0);
   }
   __ev_in.commit();
   std::string spirv_ctx =
       compute_pipeline_context(createInfoCount, pCreateInfos);
   auto real = (PFN_vkCreateComputePipelines)lookup_real_device(
       device, "vkCreateComputePipelines");
   VkResult r = real ? real(device, pipelineCache, createInfoCount, pCreateInfos,
                            pAllocator, pPipelines)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateComputePipelines", r)
   if (r == VK_SUCCESS && pPipelines) {
      __ev_out.hex("pipeline0", (uint64_t)(uintptr_t)pPipelines[0]);
   }
   log_pipeline_spirv_map("vkCreateComputePipelines", r, spirv_ctx.c_str());
   if (r == VK_SUCCESS) {
      shader_dump_dump_all_with_context("vkCreateComputePipelines",
                                        spirv_ctx.c_str());
      log_compute_isa_spirv_table("vkCreateComputePipelines", r,
                                  createInfoCount, pCreateInfos);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateGraphicsPipelines(
    VkDevice device, VkPipelineCache pipelineCache, uint32_t createInfoCount,
    const VkGraphicsPipelineCreateInfo *pCreateInfos,
    const VkAllocationCallbacks *pAllocator, VkPipeline *pPipelines) {
   VK_TRAMP_BEGIN("vkCreateGraphicsPipelines")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device)
       .hex("pipelineCache", (uint64_t)(uintptr_t)pipelineCache)
       .u64("createInfoCount", createInfoCount);
   if (pCreateInfos && createInfoCount > 0) {
      dump_graphics_pipeline_create_info(__ev_in, &pCreateInfos[0], 0);
   }
   __ev_in.commit();
   std::string spirv_ctx =
       graphics_pipeline_context(createInfoCount, pCreateInfos);
   auto real = (PFN_vkCreateGraphicsPipelines)lookup_real_device(
       device, "vkCreateGraphicsPipelines");
   VkResult r = real ? real(device, pipelineCache, createInfoCount,
                            pCreateInfos, pAllocator, pPipelines)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateGraphicsPipelines", r)
   if ((r == VK_SUCCESS || r == VK_PIPELINE_COMPILE_REQUIRED) && pPipelines &&
       createInfoCount > 0) {
      __ev_out.hex("pipeline0", (uint64_t)(uintptr_t)pPipelines[0]);
   }
   log_pipeline_spirv_map("vkCreateGraphicsPipelines", r, spirv_ctx.c_str());
   if (r == VK_SUCCESS) {
      shader_dump_dump_all_with_context("vkCreateGraphicsPipelines",
                                        spirv_ctx.c_str());
      log_graphics_isa_spirv_table("vkCreateGraphicsPipelines", r,
                                   createInfoCount, pCreateInfos);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateCommandPool(
    VkDevice device, const VkCommandPoolCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkCommandPool *pCommandPool) {
   VK_TRAMP_BEGIN("vkCreateCommandPool")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_command_pool_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateCommandPool)lookup_real_device(
       device, "vkCreateCommandPool");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pCommandPool)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateCommandPool", r)
   if (r == VK_SUCCESS && pCommandPool) {
      __ev_out.hex("pool", (uint64_t)(uintptr_t)*pCommandPool);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateSemaphore(
    VkDevice device, const VkSemaphoreCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkSemaphore *pSemaphore) {
   VK_TRAMP_BEGIN("vkCreateSemaphore")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   if (pCreateInfo) {
      __ev_in.hex("flags", pCreateInfo->flags);
   }
   __ev_in.commit();
   auto real =
       (PFN_vkCreateSemaphore)lookup_real_device(device, "vkCreateSemaphore");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pSemaphore)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateSemaphore", r)
   if (r == VK_SUCCESS && pSemaphore) {
      __ev_out.hex("semaphore", (uint64_t)(uintptr_t)*pSemaphore);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateFence(
    VkDevice device, const VkFenceCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkFence *pFence) {
   VK_TRAMP_BEGIN("vkCreateFence")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   if (pCreateInfo) {
      __ev_in.hex("flags", pCreateInfo->flags);
   }
   __ev_in.commit();
   auto real = (PFN_vkCreateFence)lookup_real_device(device, "vkCreateFence");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pFence)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateFence", r)
   if (r == VK_SUCCESS && pFence) {
      __ev_out.hex("fence", (uint64_t)(uintptr_t)*pFence);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateSampler(
    VkDevice device, const VkSamplerCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkSampler *pSampler) {
   VK_TRAMP_BEGIN("vkCreateSampler")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   if (pCreateInfo) {
      __ev_in.hex("flags", pCreateInfo->flags)
          .u64("magFilter", pCreateInfo->magFilter)
          .u64("minFilter", pCreateInfo->minFilter)
          .u64("mipmapMode", pCreateInfo->mipmapMode)
          .u64("addressModeU", pCreateInfo->addressModeU)
          .u64("addressModeV", pCreateInfo->addressModeV)
          .u64("addressModeW", pCreateInfo->addressModeW);
   }
   __ev_in.commit();
   auto real =
       (PFN_vkCreateSampler)lookup_real_device(device, "vkCreateSampler");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pSampler)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateSampler", r)
   if (r == VK_SUCCESS && pSampler) {
      __ev_out.hex("sampler", (uint64_t)(uintptr_t)*pSampler);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateSwapchainKHR(
    VkDevice device, const VkSwapchainCreateInfoKHR *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkSwapchainKHR *pSwapchain) {
   VK_TRAMP_BEGIN("vkCreateSwapchainKHR")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_swapchain_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateSwapchainKHR)lookup_real_device(
       device, "vkCreateSwapchainKHR");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pSwapchain)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateSwapchainKHR", r)
   if (r == VK_SUCCESS && pSwapchain) {
      __ev_out.hex("swapchain", (uint64_t)(uintptr_t)*pSwapchain);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkAllocateCommandBuffers(
    VkDevice device, const VkCommandBufferAllocateInfo *pAllocateInfo,
    VkCommandBuffer *pCommandBuffers) {
   VK_TRAMP_BEGIN("vkAllocateCommandBuffers")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_cmdbuf_alloc_info(__ev_in, pAllocateInfo);
   __ev_in.commit();
   auto real = (PFN_vkAllocateCommandBuffers)lookup_real_device(
       device, "vkAllocateCommandBuffers");
   VkResult r = real ? real(device, pAllocateInfo, pCommandBuffers)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkAllocateCommandBuffers", r)
   if (r == VK_SUCCESS && pCommandBuffers && pAllocateInfo &&
       pAllocateInfo->commandBufferCount > 0) {
      __ev_out.hex("cb0", (uint64_t)(uintptr_t)pCommandBuffers[0]);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkBeginCommandBuffer(
    VkCommandBuffer commandBuffer, const VkCommandBufferBeginInfo *pBeginInfo) {
   VK_TRAMP_BEGIN("vkBeginCommandBuffer")
   __ev_in.hex("cb", (uint64_t)(uintptr_t)commandBuffer);
   if (pBeginInfo) {
      __ev_in.hex("flags", pBeginInfo->flags);
   }
   __ev_in.commit();
   auto real = (PFN_vkBeginCommandBuffer)lookup_real("vkBeginCommandBuffer");
   VkResult r = real ? real(commandBuffer, pBeginInfo)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkBeginCommandBuffer", r)
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkEndCommandBuffer(
    VkCommandBuffer commandBuffer) {
   VK_TRAMP_BEGIN("vkEndCommandBuffer")
   __ev_in.hex("cb", (uint64_t)(uintptr_t)commandBuffer);
   __ev_in.commit();
   auto real = (PFN_vkEndCommandBuffer)lookup_real("vkEndCommandBuffer");
   VkResult r = real ? real(commandBuffer) : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkEndCommandBuffer", r)
   return r;
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdBindPipeline(
    VkCommandBuffer commandBuffer, VkPipelineBindPoint pipelineBindPoint,
    VkPipeline pipeline) {
   auto real = (PFN_vkCmdBindPipeline)lookup_real("vkCmdBindPipeline");
   LogBuilder("vk_enter")
       .str("fn", "vkCmdBindPipeline")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .u64("bindPoint", pipelineBindPoint)
       .hex("pipeline", (uint64_t)(uintptr_t)pipeline);
   if (real) {
      real(commandBuffer, pipelineBindPoint, pipeline);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdBindDescriptorSets(
    VkCommandBuffer commandBuffer, VkPipelineBindPoint pipelineBindPoint,
    VkPipelineLayout layout, uint32_t firstSet, uint32_t descriptorSetCount,
    const VkDescriptorSet *pDescriptorSets, uint32_t dynamicOffsetCount,
    const uint32_t *pDynamicOffsets) {
   auto real =
       (PFN_vkCmdBindDescriptorSets)lookup_real("vkCmdBindDescriptorSets");
   LogBuilder __ev("vk_enter");
   __ev.str("fn", "vkCmdBindDescriptorSets")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .u64("bindPoint", pipelineBindPoint)
       .hex("layout", (uint64_t)(uintptr_t)layout)
       .u64("firstSet", firstSet)
       .u64("descriptorSetCount", descriptorSetCount)
       .u64("dynamicOffsetCount", dynamicOffsetCount);
   if (pDescriptorSets && descriptorSetCount > 0) {
      __ev.hex("set0", (uint64_t)(uintptr_t)pDescriptorSets[0]);
   }
   __ev.commit();
   if (real) {
      real(commandBuffer, pipelineBindPoint, layout, firstSet,
           descriptorSetCount, pDescriptorSets, dynamicOffsetCount,
           pDynamicOffsets);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdDispatch(
    VkCommandBuffer commandBuffer, uint32_t groupCountX, uint32_t groupCountY,
    uint32_t groupCountZ) {
   auto real = (PFN_vkCmdDispatch)lookup_real("vkCmdDispatch");
   LogBuilder("vk_enter")
       .str("fn", "vkCmdDispatch")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .u64("x", groupCountX)
       .u64("y", groupCountY)
       .u64("z", groupCountZ);
   if (real) {
      real(commandBuffer, groupCountX, groupCountY, groupCountZ);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdDraw(
    VkCommandBuffer commandBuffer, uint32_t vertexCount,
    uint32_t instanceCount, uint32_t firstVertex, uint32_t firstInstance) {
   auto real = (PFN_vkCmdDraw)lookup_real("vkCmdDraw");
   LogBuilder("vk_enter")
       .str("fn", "vkCmdDraw")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .u64("vertexCount", vertexCount)
       .u64("instanceCount", instanceCount)
       .u64("firstVertex", firstVertex)
       .u64("firstInstance", firstInstance);
   if (real) {
      real(commandBuffer, vertexCount, instanceCount, firstVertex,
           firstInstance);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdDrawIndexed(
    VkCommandBuffer commandBuffer, uint32_t indexCount,
    uint32_t instanceCount, uint32_t firstIndex, int32_t vertexOffset,
    uint32_t firstInstance) {
   auto real = (PFN_vkCmdDrawIndexed)lookup_real("vkCmdDrawIndexed");
   LogBuilder("vk_enter")
       .str("fn", "vkCmdDrawIndexed")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .u64("indexCount", indexCount)
       .u64("instanceCount", instanceCount)
       .u64("firstIndex", firstIndex)
       .i64("vertexOffset", vertexOffset)
       .u64("firstInstance", firstInstance);
   if (real) {
      real(commandBuffer, indexCount, instanceCount, firstIndex,
           vertexOffset, firstInstance);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdDrawIndirect(
    VkCommandBuffer commandBuffer, VkBuffer buffer, VkDeviceSize offset,
    uint32_t drawCount, uint32_t stride) {
   auto real = (PFN_vkCmdDrawIndirect)lookup_real("vkCmdDrawIndirect");
   LogBuilder("vk_enter")
       .str("fn", "vkCmdDrawIndirect")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .hex("buffer", (uint64_t)(uintptr_t)buffer)
       .u64("offset", offset)
       .u64("drawCount", drawCount)
       .u64("stride", stride);
   if (real) {
      real(commandBuffer, buffer, offset, drawCount, stride);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdDrawIndexedIndirect(
    VkCommandBuffer commandBuffer, VkBuffer buffer, VkDeviceSize offset,
    uint32_t drawCount, uint32_t stride) {
   auto real =
       (PFN_vkCmdDrawIndexedIndirect)lookup_real("vkCmdDrawIndexedIndirect");
   LogBuilder("vk_enter")
       .str("fn", "vkCmdDrawIndexedIndirect")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .hex("buffer", (uint64_t)(uintptr_t)buffer)
       .u64("offset", offset)
       .u64("drawCount", drawCount)
       .u64("stride", stride);
   if (real) {
      real(commandBuffer, buffer, offset, drawCount, stride);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdPipelineBarrier(
    VkCommandBuffer commandBuffer, VkPipelineStageFlags srcStageMask,
    VkPipelineStageFlags dstStageMask, VkDependencyFlags dependencyFlags,
    uint32_t memoryBarrierCount, const VkMemoryBarrier *pMemoryBarriers,
    uint32_t bufferMemoryBarrierCount,
    const VkBufferMemoryBarrier *pBufferMemoryBarriers,
    uint32_t imageMemoryBarrierCount,
   const VkImageMemoryBarrier *pImageMemoryBarriers) {
   auto real = (PFN_vkCmdPipelineBarrier)lookup_real("vkCmdPipelineBarrier");
   LogBuilder __ev("vk_enter");
   __ev.str("fn", "vkCmdPipelineBarrier")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .hex("srcStage", srcStageMask)
       .hex("dstStage", dstStageMask)
       .hex("depFlags", dependencyFlags)
       .u64("memBarriers", memoryBarrierCount)
       .u64("bufBarriers", bufferMemoryBarrierCount)
       .u64("imgBarriers", imageMemoryBarrierCount);
   if (pImageMemoryBarriers && imageMemoryBarrierCount > 0) {
      dump_image_memory_barrier(__ev, &pImageMemoryBarriers[0], 0);
   }
   __ev.commit();
   if (real) {
      real(commandBuffer, srcStageMask, dstStageMask, dependencyFlags,
           memoryBarrierCount, pMemoryBarriers, bufferMemoryBarrierCount,
           pBufferMemoryBarriers, imageMemoryBarrierCount,
           pImageMemoryBarriers);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdCopyBufferToImage(
    VkCommandBuffer commandBuffer, VkBuffer srcBuffer, VkImage dstImage,
    VkImageLayout dstImageLayout, uint32_t regionCount,
    const VkBufferImageCopy *pRegions) {
   auto real = (PFN_vkCmdCopyBufferToImage)lookup_real("vkCmdCopyBufferToImage");
   LogBuilder __ev("vk_enter");
   __ev.str("fn", "vkCmdCopyBufferToImage")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .hex("srcBuffer", (uint64_t)(uintptr_t)srcBuffer)
       .hex("dstImage", (uint64_t)(uintptr_t)dstImage)
       .u64("dstImageLayout", dstImageLayout)
       .u64("regionCount", regionCount);
   if (pRegions && regionCount > 0) {
      dump_buffer_image_copy(__ev, &pRegions[0], 0);
   }
   if (real) {
      real(commandBuffer, srcBuffer, dstImage, dstImageLayout, regionCount,
           pRegions);
   }
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkCmdCopyImage(
    VkCommandBuffer commandBuffer, VkImage srcImage,
    VkImageLayout srcImageLayout, VkImage dstImage,
    VkImageLayout dstImageLayout, uint32_t regionCount,
    const VkImageCopy *pRegions) {
   auto real = (PFN_vkCmdCopyImage)lookup_real("vkCmdCopyImage");
   LogBuilder __ev("vk_enter");
   __ev.str("fn", "vkCmdCopyImage")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("cb", (uint64_t)(uintptr_t)commandBuffer)
       .hex("srcImage", (uint64_t)(uintptr_t)srcImage)
       .u64("srcImageLayout", srcImageLayout)
       .hex("dstImage", (uint64_t)(uintptr_t)dstImage)
       .u64("dstImageLayout", dstImageLayout)
       .u64("regionCount", regionCount);
   if (pRegions && regionCount > 0) {
      dump_image_copy(__ev, &pRegions[0], 0);
   }
   if (real) {
      real(commandBuffer, srcImage, srcImageLayout, dstImage, dstImageLayout,
           regionCount, pRegions);
   }
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkQueueSubmit(
    VkQueue queue, uint32_t submitCount, const VkSubmitInfo *pSubmits,
    VkFence fence) {
   VK_TRAMP_BEGIN("vkQueueSubmit")
   __ev_in.hex("queue", (uint64_t)(uintptr_t)queue)
       .u64("submitCount", submitCount)
       .hex("fence", (uint64_t)(uintptr_t)fence);
   if (pSubmits && submitCount > 0) {
      dump_submit_info(__ev_in, &pSubmits[0]);
   }
   __ev_in.commit();
   auto real = (PFN_vkQueueSubmit)lookup_real("vkQueueSubmit");
   VkResult r = real ? real(queue, submitCount, pSubmits, fence)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkQueueSubmit", r)
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkAcquireNextImageKHR(
    VkDevice device, VkSwapchainKHR swapchain, uint64_t timeout,
    VkSemaphore semaphore, VkFence fence, uint32_t *pImageIndex) {
   begin_frame_number();
   VK_TRAMP_BEGIN("vkAcquireNextImageKHR")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device)
       .hex("swapchain", (uint64_t)(uintptr_t)swapchain)
       .u64("timeout", timeout)
       .hex("semaphore", (uint64_t)(uintptr_t)semaphore)
       .hex("fence", (uint64_t)(uintptr_t)fence);
   __ev_in.commit();
   auto real =
       (PFN_vkAcquireNextImageKHR)lookup_real_device(device,
                                                     "vkAcquireNextImageKHR");
   VkResult r = real ? real(device, swapchain, timeout, semaphore, fence,
                            pImageIndex)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkAcquireNextImageKHR", r)
   __ev_out.hex("swapchain", (uint64_t)(uintptr_t)swapchain);
   if (pImageIndex) {
      __ev_out.u64("imageIndex", *pImageIndex);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkAcquireNextImage2KHR(
    VkDevice device, const VkAcquireNextImageInfoKHR *pAcquireInfo,
    uint32_t *pImageIndex) {
   begin_frame_number();
   VK_TRAMP_BEGIN("vkAcquireNextImage2KHR")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_acquire_info(__ev_in, pAcquireInfo);
   __ev_in.commit();
   auto real =
       (PFN_vkAcquireNextImage2KHR)lookup_real_device(device,
                                                      "vkAcquireNextImage2KHR");
   VkResult r = real ? real(device, pAcquireInfo, pImageIndex)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkAcquireNextImage2KHR", r)
   if (pAcquireInfo) {
      __ev_out.hex("swapchain", (uint64_t)(uintptr_t)pAcquireInfo->swapchain);
   }
   if (pImageIndex) {
      __ev_out.u64("imageIndex", *pImageIndex);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkQueuePresentKHR(
    VkQueue queue, const VkPresentInfoKHR *pPresentInfo) {
   VK_TRAMP_BEGIN("vkQueuePresentKHR")
   __ev_in.hex("queue", (uint64_t)(uintptr_t)queue);
   dump_present_info(__ev_in, pPresentInfo);
   if (pPresentInfo && pPresentInfo->swapchainCount > 0 &&
       pPresentInfo->pSwapchains) {
      __ev_in.hex("swapchain0",
                  (uint64_t)(uintptr_t)pPresentInfo->pSwapchains[0]);
   }
   if (pPresentInfo && pPresentInfo->swapchainCount > 0 &&
       pPresentInfo->pImageIndices) {
      __ev_in.u64("imageIndex0", pPresentInfo->pImageIndices[0]);
   }
   __ev_in.commit();
   auto real = (PFN_vkQueuePresentKHR)lookup_real("vkQueuePresentKHR");
   VkResult r = real ? real(queue, pPresentInfo)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkQueuePresentKHR", r)
   maybe_stop_after_frame();
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkQueueWaitIdle(VkQueue queue) {
   VK_TRAMP_BEGIN("vkQueueWaitIdle")
   __ev_in.hex("queue", (uint64_t)(uintptr_t)queue);
   __ev_in.commit();
   auto real = (PFN_vkQueueWaitIdle)lookup_real("vkQueueWaitIdle");
   VkResult r = real ? real(queue) : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkQueueWaitIdle", r)
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL
hook_vkDeviceWaitIdle(VkDevice device) {
   VK_TRAMP_BEGIN("vkDeviceWaitIdle")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   __ev_in.commit();
   auto real =
       (PFN_vkDeviceWaitIdle)lookup_real_device(device, "vkDeviceWaitIdle");
   VkResult r = real ? real(device) : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkDeviceWaitIdle", r)
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkCreateDescriptorPool(
    VkDevice device, const VkDescriptorPoolCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator,
    VkDescriptorPool *pDescriptorPool) {
   VK_TRAMP_BEGIN("vkCreateDescriptorPool")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_descriptor_pool_create_info(__ev_in, pCreateInfo);
   __ev_in.commit();
   auto real = (PFN_vkCreateDescriptorPool)lookup_real_device(
       device, "vkCreateDescriptorPool");
   VkResult r = real ? real(device, pCreateInfo, pAllocator, pDescriptorPool)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkCreateDescriptorPool", r)
   if (r == VK_SUCCESS && pDescriptorPool) {
      __ev_out.hex("pool", (uint64_t)(uintptr_t)*pDescriptorPool);
   }
   return r;
}

extern "C" VKAPI_ATTR VkResult VKAPI_CALL hook_vkAllocateDescriptorSets(
    VkDevice device, const VkDescriptorSetAllocateInfo *pAllocateInfo,
    VkDescriptorSet *pDescriptorSets) {
   VK_TRAMP_BEGIN("vkAllocateDescriptorSets")
   __ev_in.hex("device", (uint64_t)(uintptr_t)device);
   dump_descriptor_set_alloc_info(__ev_in, pAllocateInfo);
   __ev_in.commit();
   auto real = (PFN_vkAllocateDescriptorSets)lookup_real_device(
       device, "vkAllocateDescriptorSets");
   VkResult r = real ? real(device, pAllocateInfo, pDescriptorSets)
                     : VK_ERROR_INITIALIZATION_FAILED;
   VK_TRAMP_EXIT("vkAllocateDescriptorSets", r)
   if (r == VK_SUCCESS && pDescriptorSets && pAllocateInfo &&
       pAllocateInfo->descriptorSetCount > 0) {
      __ev_out.hex("set0", (uint64_t)(uintptr_t)pDescriptorSets[0]);
   }
   return r;
}

extern "C" VKAPI_ATTR void VKAPI_CALL hook_vkUpdateDescriptorSets(
    VkDevice device, uint32_t descriptorWriteCount,
    const VkWriteDescriptorSet *pDescriptorWrites,
    uint32_t descriptorCopyCount,
    const VkCopyDescriptorSet *pDescriptorCopies) {
   auto real =
       (PFN_vkUpdateDescriptorSets)lookup_real_device(device,
                                                     "vkUpdateDescriptorSets");
   LogBuilder("vk_enter")
       .str("fn", "vkUpdateDescriptorSets")
       .hex("real", (uint64_t)(uintptr_t)real)
       .hex("caller", (uint64_t)(uintptr_t)__builtin_return_address(0))
       .u64("frameNumber", current_frame_number())
       .hex("device", (uint64_t)(uintptr_t)device)
       .u64("writes", descriptorWriteCount)
       .u64("copies", descriptorCopyCount);
   if (real) {
      real(device, descriptorWriteCount, pDescriptorWrites,
           descriptorCopyCount, pDescriptorCopies);
   }
}

// ---------------------------------------------------------------------------
// Dispatch table for our trampolines.
// ---------------------------------------------------------------------------

struct VkFunc {
   const char *name;
   PFN_vkVoidFunction fn;
};

const VkFunc kWrappedFns[] = {
    {"vkCreateInstance", (PFN_vkVoidFunction)hook_vkCreateInstance},
    {"vkDestroyInstance", (PFN_vkVoidFunction)hook_vkDestroyInstance},
    {"vkEnumeratePhysicalDevices",
     (PFN_vkVoidFunction)hook_vkEnumeratePhysicalDevices},
    {"vkCreateDevice", (PFN_vkVoidFunction)hook_vkCreateDevice},
    {"vkDestroyDevice", (PFN_vkVoidFunction)hook_vkDestroyDevice},
    {"vkAllocateMemory", (PFN_vkVoidFunction)hook_vkAllocateMemory},
    {"vkFreeMemory", (PFN_vkVoidFunction)hook_vkFreeMemory},
    {"vkMapMemory", (PFN_vkVoidFunction)hook_vkMapMemory},
    {"vkFlushMappedMemoryRanges",
     (PFN_vkVoidFunction)hook_vkFlushMappedMemoryRanges},
    {"vkBindBufferMemory", (PFN_vkVoidFunction)hook_vkBindBufferMemory},
    {"vkBindImageMemory", (PFN_vkVoidFunction)hook_vkBindImageMemory},
    {"vkCreateBuffer", (PFN_vkVoidFunction)hook_vkCreateBuffer},
    {"vkCreateImage", (PFN_vkVoidFunction)hook_vkCreateImage},
    {"vkCreateImageView", (PFN_vkVoidFunction)hook_vkCreateImageView},
    {"vkCreateShaderModule", (PFN_vkVoidFunction)hook_vkCreateShaderModule},
    {"vkCreateDescriptorSetLayout",
     (PFN_vkVoidFunction)hook_vkCreateDescriptorSetLayout},
    {"vkCreatePipelineLayout",
     (PFN_vkVoidFunction)hook_vkCreatePipelineLayout},
    {"vkCreateRenderPass", (PFN_vkVoidFunction)hook_vkCreateRenderPass},
    {"vkCreateFramebuffer", (PFN_vkVoidFunction)hook_vkCreateFramebuffer},
    {"vkCreateComputePipelines",
     (PFN_vkVoidFunction)hook_vkCreateComputePipelines},
    {"vkCreateGraphicsPipelines",
     (PFN_vkVoidFunction)hook_vkCreateGraphicsPipelines},
    {"vkCreateCommandPool", (PFN_vkVoidFunction)hook_vkCreateCommandPool},
    {"vkCreateSemaphore", (PFN_vkVoidFunction)hook_vkCreateSemaphore},
    {"vkCreateFence", (PFN_vkVoidFunction)hook_vkCreateFence},
    {"vkCreateSampler", (PFN_vkVoidFunction)hook_vkCreateSampler},
    {"vkCreateSwapchainKHR", (PFN_vkVoidFunction)hook_vkCreateSwapchainKHR},
    {"vkAllocateCommandBuffers",
     (PFN_vkVoidFunction)hook_vkAllocateCommandBuffers},
    {"vkBeginCommandBuffer", (PFN_vkVoidFunction)hook_vkBeginCommandBuffer},
    {"vkEndCommandBuffer", (PFN_vkVoidFunction)hook_vkEndCommandBuffer},
    {"vkCmdBindPipeline", (PFN_vkVoidFunction)hook_vkCmdBindPipeline},
    {"vkCmdBindDescriptorSets",
     (PFN_vkVoidFunction)hook_vkCmdBindDescriptorSets},
    {"vkCmdDispatch", (PFN_vkVoidFunction)hook_vkCmdDispatch},
    {"vkCmdDraw", (PFN_vkVoidFunction)hook_vkCmdDraw},
    {"vkCmdDrawIndexed", (PFN_vkVoidFunction)hook_vkCmdDrawIndexed},
    {"vkCmdDrawIndirect", (PFN_vkVoidFunction)hook_vkCmdDrawIndirect},
    {"vkCmdDrawIndexedIndirect",
     (PFN_vkVoidFunction)hook_vkCmdDrawIndexedIndirect},
    {"vkCmdPipelineBarrier", (PFN_vkVoidFunction)hook_vkCmdPipelineBarrier},
    {"vkCmdCopyBufferToImage",
     (PFN_vkVoidFunction)hook_vkCmdCopyBufferToImage},
    {"vkCmdCopyImage", (PFN_vkVoidFunction)hook_vkCmdCopyImage},
    {"vkQueueSubmit", (PFN_vkVoidFunction)hook_vkQueueSubmit},
    {"vkAcquireNextImageKHR", (PFN_vkVoidFunction)hook_vkAcquireNextImageKHR},
    {"vkAcquireNextImage2KHR", (PFN_vkVoidFunction)hook_vkAcquireNextImage2KHR},
    {"vkQueuePresentKHR", (PFN_vkVoidFunction)hook_vkQueuePresentKHR},
    {"vkQueueWaitIdle", (PFN_vkVoidFunction)hook_vkQueueWaitIdle},
    {"vkDeviceWaitIdle", (PFN_vkVoidFunction)hook_vkDeviceWaitIdle},
    {"vkCreateDescriptorPool",
     (PFN_vkVoidFunction)hook_vkCreateDescriptorPool},
    {"vkAllocateDescriptorSets",
     (PFN_vkVoidFunction)hook_vkAllocateDescriptorSets},
    {"vkUpdateDescriptorSets",
     (PFN_vkVoidFunction)hook_vkUpdateDescriptorSets},
};

PFN_vkVoidFunction find_wrapper(const char *name) {
   if (!name) {
      return nullptr;
   }
   for (const VkFunc &f : kWrappedFns) {
      if (strcmp(f.name, name) == 0) {
         return f.fn;
      }
   }
   return nullptr;
}

} // namespace

void vk_hook_init() { resolve_real_loader(); }

} // namespace mali_hook

// ---------------------------------------------------------------------------
// Exported entry points. These shadow the loader's symbols at
// LD_PRELOAD time.
// ---------------------------------------------------------------------------

#define VK_HOOK_EXPORT extern "C" __attribute__((visibility("hidden"))) VKAPI_ATTR

VK_HOOK_EXPORT PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(
    VkInstance instance, const char *pName);
VK_HOOK_EXPORT PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(
    VkDevice device, const char *pName);

VK_HOOK_EXPORT PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(
    VkInstance instance, const char *pName) {
   mali_hook::resolve_real_loader();
   uint64_t caller = (uint64_t)(uintptr_t)__builtin_return_address(0);
   PFN_vkVoidFunction real = nullptr;
   PFN_vkGetInstanceProcAddr gipa =
       mali_hook::g_real_gipa.load(std::memory_order_acquire);
   if (gipa) {
      real = gipa(instance, pName);
   }
   PFN_vkVoidFunction returned = real;
   bool wrapped = false;
   if (pName && strcmp(pName, "vkGetInstanceProcAddr") == 0) {
      returned = (PFN_vkVoidFunction)vkGetInstanceProcAddr;
      wrapped = true;
   } else if (pName && strcmp(pName, "vkGetDeviceProcAddr") == 0) {
      returned = (PFN_vkVoidFunction)vkGetDeviceProcAddr;
      wrapped = true;
   } else {
      PFN_vkVoidFunction wrap = mali_hook::find_wrapper(pName);
      if (wrap) {
         mali_hook::remember_real(pName, real);
         returned = wrap;
         wrapped = true;
      }
   }
   mali_hook::log_procaddr("vkGetInstanceProcAddr", pName,
                           (uint64_t)(uintptr_t)instance, real, returned,
                           wrapped, caller);
   return returned;
}

VK_HOOK_EXPORT PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(
    VkDevice device, const char *pName) {
   mali_hook::resolve_real_loader();
   uint64_t caller = (uint64_t)(uintptr_t)__builtin_return_address(0);
   PFN_vkVoidFunction real = nullptr;
   PFN_vkGetDeviceProcAddr gdpa =
       mali_hook::g_real_gdpa.load(std::memory_order_acquire);
   if (gdpa) {
      real = gdpa(device, pName);
   }
   PFN_vkVoidFunction returned = real;
   bool wrapped = false;
   if (pName && strcmp(pName, "vkGetInstanceProcAddr") == 0) {
      returned = (PFN_vkVoidFunction)vkGetInstanceProcAddr;
      wrapped = true;
   } else if (pName && strcmp(pName, "vkGetDeviceProcAddr") == 0) {
      returned = (PFN_vkVoidFunction)vkGetDeviceProcAddr;
      wrapped = true;
   } else {
      PFN_vkVoidFunction wrap = mali_hook::find_wrapper(pName);
      if (wrap) {
         mali_hook::remember_real(pName, real);
         returned = wrap;
         wrapped = true;
      }
   }
   mali_hook::log_procaddr("vkGetDeviceProcAddr", pName,
                           (uint64_t)(uintptr_t)device, real, returned,
                           wrapped, caller);
   return returned;
}

extern "C" __attribute__((visibility("default"))) void *dlsym(
    void *handle, const char *name) {
   void *real = mali_hook::call_real_dlsym(handle, name);
   uint64_t caller = (uint64_t)(uintptr_t)__builtin_return_address(0);
   if (name && strcmp(name, "vkGetInstanceProcAddr") == 0) {
      void *returned = (void *)vkGetInstanceProcAddr;
      mali_hook::remember_real(name, (PFN_vkVoidFunction)real);
      mali_hook::log_procaddr("dlsym", name, (uint64_t)(uintptr_t)handle,
                              (PFN_vkVoidFunction)real,
                              (PFN_vkVoidFunction)returned, true, caller);
      return returned;
   }
   if (name && strcmp(name, "vkGetDeviceProcAddr") == 0) {
      void *returned = (void *)vkGetDeviceProcAddr;
      mali_hook::remember_real(name, (PFN_vkVoidFunction)real);
      mali_hook::log_procaddr("dlsym", name, (uint64_t)(uintptr_t)handle,
                              (PFN_vkVoidFunction)real,
                              (PFN_vkVoidFunction)returned, true, caller);
      return returned;
   }
   PFN_vkVoidFunction wrap = mali_hook::find_wrapper(name);
   if (wrap) {
      mali_hook::remember_real(name, (PFN_vkVoidFunction)real);
      mali_hook::log_procaddr("dlsym", name, (uint64_t)(uintptr_t)handle,
                              (PFN_vkVoidFunction)real, wrap, true, caller);
      return (void *)wrap;
   }
   return real;
}

VK_HOOK_EXPORT VkResult VKAPI_CALL vkCreateInstance(
    const VkInstanceCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkInstance *pInstance) {
   mali_hook::resolve_real_loader();
   return mali_hook::hook_vkCreateInstance(pCreateInfo, pAllocator, pInstance);
}

VK_HOOK_EXPORT VkResult VKAPI_CALL
vkEnumerateInstanceVersion(uint32_t *pApiVersion) {
   mali_hook::resolve_real_loader();
   auto real = (PFN_vkEnumerateInstanceVersion)mali_hook::lookup_real(
       "vkEnumerateInstanceVersion");
   return real ? real(pApiVersion) : VK_ERROR_INITIALIZATION_FAILED;
}

VK_HOOK_EXPORT VkResult VKAPI_CALL vkEnumerateInstanceExtensionProperties(
    const char *pLayerName, uint32_t *pPropertyCount,
    VkExtensionProperties *pProperties) {
   mali_hook::resolve_real_loader();
   auto real =
       (PFN_vkEnumerateInstanceExtensionProperties)mali_hook::lookup_real(
           "vkEnumerateInstanceExtensionProperties");
   return real ? real(pLayerName, pPropertyCount, pProperties)
               : VK_ERROR_INITIALIZATION_FAILED;
}

VK_HOOK_EXPORT VkResult VKAPI_CALL vkEnumerateInstanceLayerProperties(
    uint32_t *pPropertyCount, VkLayerProperties *pProperties) {
   mali_hook::resolve_real_loader();
   auto real = (PFN_vkEnumerateInstanceLayerProperties)mali_hook::lookup_real(
       "vkEnumerateInstanceLayerProperties");
   return real ? real(pPropertyCount, pProperties)
               : VK_ERROR_INITIALIZATION_FAILED;
}
