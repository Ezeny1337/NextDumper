#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

MODE="verify"
ABI="arm64-v8a"
BUILD_DIR=""
JOBS=""
STRIP_RELEASE=1

usage() {
    cat <<'EOF'
Usage: ./build.sh [options]

Build modes:
  verify       Fast compile verification build (default, Release + O3)
  release      Size-optimized release build without NDEBUG, stripped

Options:
  --mode MODE          verify or release
  --abi ABI            arm64-v8a or armeabi-v7a (default: arm64-v8a)
  --build-dir DIR      Override the CMake build directory
  --jobs N             Parallel build jobs (default: nproc or 1)
  --no-strip           Keep symbols for release mode
  -h, --help           Show this help

Environment:
  ANDROID_NDK_HOME     Android NDK directory
  ANDROID_NDK_ROOT     Fallback NDK directory
  ANDROID_SDK_ROOT     Used to discover the newest installed NDK

Examples:
  ./build.sh
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
        --mode)
            (($# >= 2)) || die "--mode requires a value"
            MODE="$2"
            shift 2
            ;;
        --abi)
            (($# >= 2)) || die "--abi requires a value"
            ABI="$2"
            shift 2
            ;;
        --build-dir)
            (($# >= 2)) || die "--build-dir requires a value"
            BUILD_DIR="$2"
            shift 2
            ;;
        --jobs)
            (($# >= 2)) || die "--jobs requires a value"
            JOBS="$2"
            shift 2
            ;;
        --no-strip)
            STRIP_RELEASE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

case "$MODE" in
    verify|release) ;;
    *) die "unsupported mode '$MODE'; use verify or release" ;;
esac

case "$ABI" in
    arm64-v8a|armeabi-v7a) ;;
    *) die "unsupported ABI '$ABI'; use arm64-v8a or armeabi-v7a" ;;
esac

command -v cmake >/dev/null 2>&1 || die "cmake was not found in PATH"
command -v ninja >/dev/null 2>&1 || die "ninja was not found in PATH"

if [[ -z "$JOBS" ]]; then
    if command -v nproc >/dev/null 2>&1; then
        JOBS="$(nproc)"
    else
        JOBS=1
    fi
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "jobs must be a positive integer"

NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -z "$NDK_HOME" && -n "${ANDROID_SDK_ROOT:-}" ]]; then
    NDK_HOME="$(find "$ANDROID_SDK_ROOT/ndk" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort -V | tail -n 1 || true)"
fi
[[ -n "$NDK_HOME" ]] || die "set ANDROID_NDK_HOME or ANDROID_NDK_ROOT"
[[ -d "$NDK_HOME" ]] || die "NDK directory does not exist: $NDK_HOME"

TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake"
[[ -f "$TOOLCHAIN_FILE" ]] || die "Android CMake toolchain was not found: $TOOLCHAIN_FILE"

if [[ -z "$BUILD_DIR" ]]; then
    BUILD_DIR="$SCRIPT_DIR/build/android-${ABI}-${MODE}"
elif [[ "$BUILD_DIR" != /* ]]; then
    BUILD_DIR="$SCRIPT_DIR/$BUILD_DIR"
fi

CONFIGURE_ARGS=(
    -S "$SCRIPT_DIR"
    -B "$BUILD_DIR"
    -G Ninja
    "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE"
    "-DANDROID_ABI=$ABI"
    -DANDROID_PLATFORM=android-29
    -DNEXTDUMPER_ENABLE_THINLTO=ON
)

case "$MODE" in
    verify)
        CONFIGURE_ARGS+=(
            -DCMAKE_BUILD_TYPE=Release
            -DNEXTDUMPER_OPTIMIZE_FOR_SIZE=OFF
        )
        ;;
    release)
        CONFIGURE_ARGS+=(
            -DCMAKE_BUILD_TYPE=Release
            -DNEXTDUMPER_OPTIMIZE_FOR_SIZE=ON
        )
        ;;
esac

printf 'Configuring %s (%s) in %s\n' "$MODE" "$ABI" "$BUILD_DIR"
cmake "${CONFIGURE_ARGS[@]}"

printf 'Building with %s parallel job(s)\n' "$JOBS"
cmake --build "$BUILD_DIR" --parallel "$JOBS"

ARTIFACT="$BUILD_DIR/NextDumper"
[[ -x "$ARTIFACT" ]] || die "build completed but artifact was not found: $ARTIFACT"

if [[ "$MODE" == release && "$STRIP_RELEASE" == 1 ]]; then
    STRIP_TOOL="$(command -v llvm-strip || true)"
    if [[ -z "$STRIP_TOOL" ]]; then
        HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
        CANDIDATE="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/llvm-strip"
        [[ -x "$CANDIDATE" ]] && STRIP_TOOL="$CANDIDATE"
    fi
    [[ -n "$STRIP_TOOL" ]] || die "llvm-strip was not found; use --no-strip to keep the unstripped release"
    "$STRIP_TOOL" --strip-unneeded "$ARTIFACT"
    printf 'Stripped release artifact with %s\n' "$STRIP_TOOL"
fi

printf 'Built: %s\n' "$ARTIFACT"
