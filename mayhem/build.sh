#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Restore the meson wrap dependencies pre-fetched by the Dockerfile (air-gapped, and survives a
# `git clean -ffdX`, which removes the gitignored subprojects/<dep> directories).
for d in /opt/rizin-subprojects/*; do
  [ -e "subprojects/$(basename "$d")" ] || cp -a "$d" subprojects/
done

ASAN_PREFIX="$SRC/build-install-asan"
TEST_PREFIX="$SRC/build-install-test"
# The relaxed UBSan check: rizin calls typed iterators / callbacks through a generic function-pointer type
# everywhere (-fsanitize=function floods on the very first call); every other UBSan check stays halting.
RZ_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link -fno-sanitize=function $DEBUG_FLAGS"

# meson_setup <builddir> <prefix> <extra meson args...>  (re-runnable: reconfigures an existing builddir)
meson_setup() {
  local bdir="$1" prefix="$2"; shift 2
  local mode=()
  [ -f "$bdir/build.ninja" ] && mode=(--reconfigure)
  meson setup "${mode[@]}" "$bdir" --prefix="$prefix" --wrap-mode=nodownload -Dlocal=enabled "$@"
}

# 1) The project itself, sanitized + DWARF 3 (shared libs; b_lundef=false so the .so files resolve the
#    sanitizer runtime from the executable that loads them).
meson_setup build-asan "$ASAN_PREFIX" --buildtype=plain -Doptimization=1 -Ddebug=false -Db_lundef=false \
  -Dc_args="$RZ_FLAGS" -Dcpp_args="$RZ_FLAGS" -Dc_link_args="$SANITIZER_FLAGS" -Dcpp_link_args="$SANITIZER_FLAGS" \
  -Denable_tests=false -Denable_rz_test=false
meson compile -C build-asan -j "$MAYHEM_JOBS"
meson install -C build-asan --no-rebuild >/dev/null

# 2) Harnesses: libFuzzer binary + run-once standalone reproducer each; both link the sanitized rizin libs.
export PKG_CONFIG_PATH="$(dirname "$(find "$ASAN_PREFIX" -name rz_arch.pc | head -1)")"
LIBDIR="$(dirname "$PKG_CONFIG_PATH")"
RZ_CFLAGS="$(pkg-config --cflags rz_arch)"
RZ_LIBS="$(pkg-config --libs rz_arch) -Wl,-rpath,$LIBDIR"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

build_harness() {   # <name> <source> <compiler>
  local name="$1" src="$2" cc="$3"
  $cc $SANITIZER_FLAGS -fno-sanitize=function $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$src" /tmp/lsan_off.o \
    $RZ_CFLAGS $RZ_LIBS -o "/mayhem/$name"
  $cc $SANITIZER_FLAGS -fno-sanitize=function $DEBUG_FLAGS "$src" /tmp/standalone_main.o /tmp/lsan_off.o \
    $RZ_CFLAGS $RZ_LIBS -o "/mayhem/$name-standalone"
}
build_harness fuzz_rz_bin "$SRC/mayhem/fuzz_rz_bin.c" "$CC"
build_harness fuzz_rz_asm_disasm "$SRC/mayhem/fuzz_rz_asm_disasm.c" "$CC"
build_harness fuzz_rz_asm_token_string_new "$SRC/mayhem/fuzz_rz_asm_token_string_new.cpp" "$CXX"

# 3) The project's test tooling (rz-test + rz-asm/rizin/rz-ax/rz-hash/rz-bin), built with NORMAL flags in a
#    separate tree so test.sh stays an honest functional oracle.
meson_setup build-test "$TEST_PREFIX" --buildtype=release -Dc_args="$COVERAGE_FLAGS" -Dcpp_args="$COVERAGE_FLAGS" \
  -Dc_link_args="$COVERAGE_FLAGS" -Dcpp_link_args="$COVERAGE_FLAGS" -Denable_tests=false -Denable_rz_test=true
meson compile -C build-test -j "$MAYHEM_JOBS"
meson install -C build-test --no-rebuild >/dev/null
