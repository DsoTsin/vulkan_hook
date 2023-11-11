#include <android/native_window_jni.h>
#include <android/hardware_buffer.h>
#include <android/log.h>
#include <android/surface_control.h>
#include <cstdlib>
#include <dlfcn.h>
#include <jni.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define TAG "MANET_REPLAY_BRIDGE"

namespace {

ANativeWindow *g_window = nullptr;
ASurfaceControl *g_surface_control = nullptr;
std::vector<AHardwareBuffer *> g_buffers;
std::vector<int> g_import_fds;
using ReplayLiveFromEnv = int (*)(const char *);

void clear_replay_buffers() {
    for (int fd : g_import_fds) {
        if (fd >= 0) {
            close(fd);
        }
    }
    g_import_fds.clear();
    for (AHardwareBuffer *buffer : g_buffers) {
        if (buffer) {
            AHardwareBuffer_release(buffer);
        }
    }
    g_buffers.clear();
}

void replace_window(JNIEnv *env, jobject surface) {
    if (g_window) {
        ANativeWindow_release(g_window);
        g_window = nullptr;
    }
    if (surface) {
        g_window = ANativeWindow_fromSurface(env, surface);
    }
}

int export_first_dmabuf_fd(AHardwareBuffer *buffer) {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "socketpair failed");
        return -1;
    }

    int send_ret = AHardwareBuffer_sendHandleToUnixSocket(buffer, sockets[0]);
    if (send_ret != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "AHardwareBuffer_sendHandleToUnixSocket failed ret=%d",
                            send_ret);
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }

    char data[64];
    char control[CMSG_SPACE(sizeof(int) * 8)];
    iovec iov = {data, sizeof(data)};
    msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t recv_ret = recvmsg(sockets[1], &msg, 0);
    close(sockets[0]);
    close(sockets[1]);
    if (recv_ret < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "recvmsg hardware buffer handle failed");
        return -1;
    }

    int first_fd = -1;
    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        int count = static_cast<int>((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
        int *fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));
        for (int i = 0; i < count; i++) {
            if (first_fd < 0) {
                first_fd = fds[i];
            } else {
                close(fds[i]);
            }
        }
    }
    return first_fd;
}

bool prepare_import_buffers(int width, int height) {
    clear_replay_buffers();
    if (width <= 0 || height <= 0) {
        return false;
    }

    AHardwareBuffer_Desc desc = {};
    desc.width = static_cast<uint32_t>(width);
    desc.height = static_cast<uint32_t>(height);
    desc.layers = 1;
    desc.format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM;
    desc.usage = AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT |
                 AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                 AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY;

    const int buffer_count = 5;
    for (int i = 0; i < buffer_count; i++) {
        AHardwareBuffer *buffer = nullptr;
        int ret = AHardwareBuffer_allocate(&desc, &buffer);
        if (ret != 0 || !buffer) {
            __android_log_print(ANDROID_LOG_ERROR, TAG,
                                "AHardwareBuffer_allocate[%d] failed ret=%d", i, ret);
            clear_replay_buffers();
            return false;
        }
        int fd = export_first_dmabuf_fd(buffer);
        if (fd < 0) {
            AHardwareBuffer_release(buffer);
            clear_replay_buffers();
            return false;
        }
        AHardwareBuffer_Desc live_desc = {};
        AHardwareBuffer_describe(buffer, &live_desc);
        __android_log_print(ANDROID_LOG_INFO, TAG,
                            "import buffer[%d] fd=%d %ux%u stride=%u format=%u usage=0x%llx",
                            i, fd, live_desc.width, live_desc.height, live_desc.stride,
                            live_desc.format,
                            static_cast<unsigned long long>(live_desc.usage));
        g_buffers.push_back(buffer);
        g_import_fds.push_back(fd);
    }

    std::ostringstream stream;
    for (size_t i = 0; i < g_import_fds.size(); i++) {
        if (i != 0) {
            stream << ",";
        }
        stream << g_import_fds[i];
    }
    std::string fds = stream.str();
    setenv("MANET_REPLAY_IMPORT_FDS", fds.c_str(), 1);
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "MANET_REPLAY_IMPORT_FDS=%s", fds.c_str());
    return true;
}

void present_replay_buffer(size_t index) {
    if (!g_window || index >= g_buffers.size()) {
        return;
    }
    if (!g_surface_control) {
        g_surface_control = ASurfaceControl_createFromWindow(g_window, "manet-replay");
    }
    if (!g_surface_control) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "ASurfaceControl_createFromWindow failed");
        return;
    }
    ASurfaceTransaction *transaction = ASurfaceTransaction_create();
    if (!transaction) {
        return;
    }
    ASurfaceTransaction_setVisibility(transaction, g_surface_control,
                                      ASURFACE_TRANSACTION_VISIBILITY_SHOW);
    ASurfaceTransaction_setZOrder(transaction, g_surface_control, 1);
    ASurfaceTransaction_setBuffer(transaction, g_surface_control, g_buffers[index], -1);
    ASurfaceTransaction_apply(transaction);
    ASurfaceTransaction_delete(transaction);
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "present replay buffer index=%zu", index);
}

ReplayLiveFromEnv load_replay_entry() {
    void *handle = dlopen("libmanet_replay_jni.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        handle = dlopen("/data/local/tmp/manet/libmanet_replay_jni.so",
                        RTLD_NOW | RTLD_LOCAL);
    }
    if (!handle) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "dlopen libmanet_replay_jni.so failed: %s",
                            dlerror());
        return nullptr;
    }
    void *sym = dlsym(handle, "manet_replay_live_from_env");
    if (!sym) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "dlsym manet_replay_live_from_env failed: %s",
                            dlerror());
        return nullptr;
    }
    return reinterpret_cast<ReplayLiveFromEnv>(sym);
}

} // namespace

extern "C" JNIEXPORT void JNICALL
Java_de_saschawillems_vulkanSample_ManetReplayActivity_nativeSurfaceReady(
        JNIEnv *env, jclass, jobject surface, jstring tracePath, jboolean runReplay,
        jboolean allowKick, jboolean submitKick, jint importLimit, jint replayWidth,
        jint replayHeight) {
    replace_window(env, surface);
    const char *trace = tracePath ? env->GetStringUTFChars(tracePath, nullptr) : nullptr;
    int width = g_window ? ANativeWindow_getWidth(g_window) : 0;
    int height = g_window ? ANativeWindow_getHeight(g_window) : 0;
    int import_width = replayWidth > 0 ? replayWidth : width;
    int import_height = replayHeight > 0 ? replayHeight : height;
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "surface ready window=%p size=%dx%d importSize=%dx%d trace=%s runReplay=%d allowKick=%d submitKick=%d importLimit=%d",
                        g_window, width, height, import_width, import_height, trace ? trace : "",
                        runReplay ? 1 : 0, allowKick ? 1 : 0, submitKick ? 1 : 0,
                        static_cast<int>(importLimit));
    if (runReplay && trace) {
        if (allowKick) {
            if (submitKick) {
                setenv("MANET_REPLAY_ALLOW_KICK", "1", 1);
            } else {
                unsetenv("MANET_REPLAY_ALLOW_KICK");
            }
            if (importLimit > 0) {
                std::string limit = std::to_string(importLimit);
                setenv("MANET_REPLAY_MEM_IMPORT_LIMIT", limit.c_str(), 1);
            } else {
                unsetenv("MANET_REPLAY_MEM_IMPORT_LIMIT");
            }
            prepare_import_buffers(import_width, import_height);
        } else {
            unsetenv("MANET_REPLAY_ALLOW_KICK");
            unsetenv("MANET_REPLAY_MEM_IMPORT_LIMIT");
            unsetenv("MANET_REPLAY_IMPORT_FDS");
        }
        ReplayLiveFromEnv entry = load_replay_entry();
        if (entry) {
            int ret = entry(trace);
            __android_log_print(ANDROID_LOG_INFO, TAG,
                                "manet_replay_live_from_env ret=%d", ret);
            if (ret == 0 && submitKick && !g_buffers.empty()) {
                present_replay_buffer(0);
            }
        }
    }
    if (trace) {
        env->ReleaseStringUTFChars(tracePath, trace);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_de_saschawillems_vulkanSample_ManetReplayActivity_nativeSurfaceResized(
        JNIEnv *env, jclass, jobject surface, jint width, jint height) {
    replace_window(env, surface);
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "surface resized window=%p size=%dx%d",
                        g_window, (int)width, (int)height);
}

extern "C" JNIEXPORT void JNICALL
Java_de_saschawillems_vulkanSample_ManetReplayActivity_nativeSurfaceDestroyed(
        JNIEnv *, jclass) {
    if (g_surface_control) {
        ASurfaceControl_release(g_surface_control);
        g_surface_control = nullptr;
    }
    clear_replay_buffers();
    if (g_window) {
        ANativeWindow_release(g_window);
        g_window = nullptr;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "surface destroyed");
}
