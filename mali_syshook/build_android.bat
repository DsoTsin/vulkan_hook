@echo off
setlocal

rem ---------------------------------------------------------------------------
rem mali_syshook — Android arm64 cross-build via NDK r25.
rem
rem Output: build-android\libmali_syshook.so
rem Deploy: adb push build-android\libmali_syshook.so /data/local/tmp/
rem Use:    LD_PRELOAD=/data/local/tmp/libmali_syshook.so <victim>
rem ---------------------------------------------------------------------------

set "NDK=F:\Android\Sdk\ndk\25.1.8937393"
if not exist "%NDK%" (
    echo Error: NDK not found at %NDK%
    exit /b 1
)

set "BUILD_DIR=%~dp0build-android"

if not exist "%BUILD_DIR%\build.ninja" (
    cmake -S "%~dp0" -B "%BUILD_DIR%" -G Ninja ^
        -DCMAKE_TOOLCHAIN_FILE=%NDK%\build\cmake\android.toolchain.cmake ^
        -DANDROID_ABI=arm64-v8a ^
        -DANDROID_PLATFORM=android-29 ^
        -DCMAKE_BUILD_TYPE=Release
    if errorlevel 1 exit /b %errorlevel%
)

cmake --build "%BUILD_DIR%" --target mali_syshook
exit /b %errorlevel%
