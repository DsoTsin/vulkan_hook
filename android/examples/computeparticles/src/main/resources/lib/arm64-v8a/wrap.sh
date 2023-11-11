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
LOG_DIR=/data/user/0/de.saschawillems.vulkanComputeparticles/files
mkdir -p "$LOG_DIR"
export MALI_HOOK_LOG="$LOG_DIR/mali_hook_computeparticles.jsonl"
export MALI_HOOK_BLOB_DIR="$LOG_DIR/mali_hook_computeparticles.blobs"
export MALI_HOOK_REPLAY_SNAPSHOT=1
export MALI_HOOK_REPLAY_SNAPSHOT_MAX_BYTES=1048576
export MALI_HOOK_MAX_FRAMES=2
export LD_PRELOAD=$HERE/libmali_syshook.so
exec $cmd
