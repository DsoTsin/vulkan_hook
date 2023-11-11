#!/system/bin/sh
cmd=$1
shift

os_version=$(getprop ro.build.version.sdk)

if [ "$os_version" -eq "27" ]; then
  cmd="$cmd -Xrunjdwp:transport=dt_android_adb,suspend=n,server=y -Xcompiler-option --debuggable $@"
elif [ "$os_version" -eq "28" ]; then
  cmd="$cmd -XjdwpProvider:adbconnection -XjdwpOptions:suspend=n,server=y -Xcompiler-option --debuggable $@"
else
  cmd="$cmd -XjdwpProvider:adbconnection -XjdwpOptions:suspend=n,server=y $@"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR=/sdcard/Android/data/de.saschawillems.vulkanTriangle/files
mkdir -p "$LOG_DIR"
export MALI_HOOK_LOG="$LOG_DIR/mali_hook_triangle.jsonl"
export MALI_HOOK_MAX_FRAMES=2
export MALI_HOOK_REPLAY_SNAPSHOT=1
# dump_blob_file is page-resilient now (mincore per page, zero-fill
# absent pages) so the 4 MB default cap captures EXEC-zone shader
# binaries (~85 KB in) and the 16 MB pools without EFAULT truncation.
export LD_PRELOAD=$HERE/libmali_syshook.so
exec $cmd
