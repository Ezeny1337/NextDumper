#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="debug"
ABI="arm64-v8a"
BUILD_DIR=""
JOBS=""
STRIP_RELEASE=1
ANDROID_PLATFORM="android-29"

show_usage() {
    cat <<'EOF'
Usage: ./build.sh [options]

Build modes:
  debug        Unoptimized build with debug information and assertions (default)
  release      Performance-optimized build (O2 + ThinLTO) with assertions, stripped

Options:
  --mode MODE          debug or release
  --abi ABI            arm64-v8a or armeabi-v7a (default: arm64-v8a)
  --build-dir DIR      Override the CMake build directory
  --jobs N             Parallel build jobs (default: nproc or 1)
  --no-strip           Keep symbols for release mode
  -h, --help           Show this help

Environment:
  ANDROID_NDK_HOME      Android NDK directory
  ANDROID_NDK_ROOT      Fallback NDK directory
  ANDROID_SDK_ROOT      Used to discover the newest installed NDK
  NEXTDUMPER_USE_CCACHE Use ccache when set to 1 (default: 0)

Examples:
  ./build.sh
  ./build.sh --mode debug --jobs 4
  ./build.sh --mode release --abi arm64-v8a
  ./build.sh --mode release --abi armeabi-v7a --jobs 4
EOF
}

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --mode|--abi|--build-dir|--jobs)
            (($# >= 2)) || die "$1 requires a value"
            case "$1" in
                --mode) MODE="$2" ;;
                --abi) ABI="$2" ;;
                --build-dir) BUILD_DIR="$2" ;;
                --jobs) JOBS="$2" ;;
            esac
            shift 2
            ;;
        --no-strip)
            STRIP_RELEASE=0
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$MODE" in
    debug|release) ;;
    *) die "unsupported mode '$MODE'; use debug or release" ;;
esac

case "$ABI" in
    arm64-v8a|armeabi-v7a) ;;
    *) die "unsupported ABI '$ABI'; use arm64-v8a or armeabi-v7a" ;;
esac

if [[ -z "$BUILD_DIR" ]]; then
    BUILD_DIR="$SCRIPT_DIR/build/android-$ABI-$MODE"
elif [[ "$BUILD_DIR" != /* ]]; then
    BUILD_DIR="$SCRIPT_DIR/$BUILD_DIR"
fi
ELF_OUTPUT="$BUILD_DIR/NextDumper"

check_build_tools() {
    command -v cmake >/dev/null 2>&1 || die "cmake was not found in PATH"
    command -v ninja >/dev/null 2>&1 || die "ninja was not found in PATH"
}

find_ndk() {
    NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    if [[ -z "$NDK_HOME" && -n "${ANDROID_SDK_ROOT:-}" && -d "$ANDROID_SDK_ROOT/ndk" ]]; then
        NDK_HOME="$(find "$ANDROID_SDK_ROOT/ndk" -mindepth 1 -maxdepth 1 -type d -print | sort -V | tail -n 1)"
    fi
    [[ -n "$NDK_HOME" ]] || die "set ANDROID_NDK_HOME or ANDROID_NDK_ROOT"
    [[ -d "$NDK_HOME" ]] || die "NDK directory does not exist: $NDK_HOME"
    TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake"
    [[ -f "$TOOLCHAIN_FILE" ]] || die "Android CMake toolchain was not found: $TOOLCHAIN_FILE"
}

build_executable() {
    check_build_tools
    find_ndk

    if [[ -z "$JOBS" ]]; then
        if command -v nproc >/dev/null 2>&1; then
            JOBS="$(nproc)"
        else
            JOBS=1
        fi
    fi
    [[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "jobs must be a positive integer"

    local compiler_launcher=""
    case "${NEXTDUMPER_USE_CCACHE:-0}" in
        0) ;;
        1)
            command -v ccache >/dev/null 2>&1 || die "ccache was requested but not found in PATH"
            compiler_launcher="ccache"
            ;;
        *) die "NEXTDUMPER_USE_CCACHE must be 0 or 1" ;;
    esac

    local build_type="Debug"
    [[ "$MODE" != release ]] || build_type="Release"
    local strip_release="ON"
    [[ "$STRIP_RELEASE" == 1 ]] || strip_release="OFF"
    cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -G Ninja \
        "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE" \
        "-DANDROID_ABI=$ABI" \
        "-DANDROID_PLATFORM=$ANDROID_PLATFORM" \
        "-DCMAKE_BUILD_TYPE=$build_type" \
        "-DNEXTDUMPER_STRIP_RELEASE=$strip_release" \
        "-DCMAKE_CXX_COMPILER_LAUNCHER=$compiler_launcher"
    cmake --build "$BUILD_DIR" --parallel "$JOBS"
    [[ -f "$ELF_OUTPUT" ]] || die "build completed but artifact was not found: $ELF_OUTPUT"
    printf 'Built: %s\n' "$ELF_OUTPUT"
}

build_executable
