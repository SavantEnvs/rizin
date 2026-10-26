#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/build-install-test/bin"
export PATH="$BIN:$PATH"
[ -x "$BIN/rz-test" ] && [ -x "$BIN/rizin" ] && [ -x "$BIN/rz-asm" ] \
  || { echo "mayhem/build.sh did not produce the test tooling in $BIN" >&2; emit_ctrf "rz-test" 0 1 0; exit 1; }

passed=0; failed=0; skipped=0

# known-answer checks: <name> <expected output> <command...>
check() {
  local name="$1" want="$2" got; shift 2
  got="$("$@" 2>&1)"
  if [ "$got" = "$want" ] || { [ "${CHECK_SUBSTR:-0}" = 1 ] && [[ "$got" == *"$want"* ]]; }; then passed=$((passed+1)); echo "PASS $name"
  else failed=$((failed+1)); echo "FAIL $name: wanted [$want], got [$got]"; fi
}

check "rz-asm assemble x86_64"    "b801000000"   rz-asm -a x86 -b 64 "mov eax, 1"
check "rz-asm assemble arm64"     "20008052"     rz-asm -a arm -b 64 "mov w0, 1"
check "rz-asm disassemble x86_64" "mov eax, 0x01" rz-asm -a x86 -b 64 -d b801000000
check "rz-asm disassemble arm64"  "mov w0, 1"    rz-asm -a arm -b 64 -d 20008052
check "rz-ax hex to dec"          "16"           rz-ax 0x10
check "rz-ax dec to hex"          "0xff"         rz-ax 255
CHECK_SUBSTR=1
check "rz-hash md5"               "md5: 5d41402abc4b2a76b9719d911017c592" rz-hash -a md5 -s hello
check "rz-hash sha256"            "sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" rz-hash -a sha256 -s hello
check "rizin disasm via core"     "mov eax, 0x01" rizin -N -q -e scr.color=0 -c "wx b801000000; pi 1" malloc://16
check "rizin write+read via core" "48656c6c6f21" rizin -N -q -e scr.color=0 -w -c "w Hello!; p8 6" malloc://16
check "rz-bin info on an ELF"      "bintype  elf" env RZ_COLOR=0 rz-bin -I "$BIN/rizin"
CHECK_SUBSTR=0

# rizin's own regression suite for the assembler/disassembler (known input -> known output, ~26k cases).
# rz-test prints cumulative "<n> OK <n> BR <n> XX <n> FX" per directory: OK passed, BR known-broken
# (skipped), XX failed, FX a known-broken case that now passes.
RZTLOG="$(mktemp)"
( cd "$SRC/test" && rz-test -L -j "$MAYHEM_JOBS" db/asm ) >"$RZTLOG" 2>&1 || true
tail -n 12 "$RZTLOG"
read -r ok br xx fx <<<"$(sed -n 's/.*[[:space:]]\([0-9]\+\) OK[[:space:]]\+\([0-9]\+\) BR[[:space:]]\+\([0-9]\+\) XX[[:space:]]\+\([0-9]\+\) FX.*/\1 \2 \3 \4/p' "$RZTLOG" | sort -n | tail -1)"
if [ -z "${ok:-}" ] || [ "$ok" -lt 1000 ]; then
  failed=$((failed+1)); echo "FAIL rz-test db/asm produced no results"
else
  passed=$((passed+ok+fx)); failed=$((failed+xx)); skipped=$((skipped+br))
fi
rm -f "$RZTLOG"

emit_ctrf "rz-test" "$passed" "$failed" "$skipped"
