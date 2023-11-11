# mali_syshook — Android arm64 cross-build via NDK r25.
# Output:  build-android\libmali_syshook.so
# Deploy:  adb push build-android\libmali_syshook.so /data/local/tmp/
# Use:     LD_PRELOAD=/data/local/tmp/libmali_syshook.so <victim>

$NDK = 'F:\Android\Sdk\ndk\25.1.8937393'
if (-not (Test-Path $NDK)) {
    Write-Error "NDK not found at $NDK"
}

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $Here 'build-android'

if (-not (Test-Path (Join-Path $BuildDir 'build.ninja'))) {
    cmake -S $Here -B $BuildDir -G Ninja `
        "-DCMAKE_TOOLCHAIN_FILE=$NDK\build\cmake\android.toolchain.cmake" `
        '-DANDROID_ABI=arm64-v8a' `
        '-DANDROID_PLATFORM=android-29' `
        '-DCMAKE_BUILD_TYPE=Release'
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

cmake --build $BuildDir --target mali_syshook
exit $LASTEXITCODE
