#!/bin/sh
# Run from any directory. Reports include production lines, excluding test modules.
set -eu

if [ "$(uname -s)" != Linux ]; then
  echo "Run Linux coverage on a Linux host." >&2
  exit 1
fi
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
coverage_dir=${KV_COVERAGE_DIR:-"$repo_dir/rust/target/linux-coverage"}
llvm_bin=${KV_LLVM_BIN:-"$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"}
for tool in llvm-cov llvm-profdata; do
  if [ ! -x "$llvm_bin/$tool" ]; then
    echo "Missing $tool; install rustup component add llvm-tools-preview, or set KV_LLVM_BIN." >&2
    exit 1
  fi
done
mkdir -p "$coverage_dir"
coverage_dir=$(CDPATH= cd -- "$coverage_dir" && pwd)
profile_dir=$(mktemp -d "$coverage_dir/profiles.XXXXXX")
export LLVM_PROFILE_FILE="$profile_dir/%p-%m.profraw"
export RUSTFLAGS="${RUSTFLAGS:-} -C instrument-coverage"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$coverage_dir/build"}
cd "$repo_dir/rust"
test_status=0
cargo test --workspace --locked --no-fail-fast --message-format=json \
  > "$coverage_dir/cargo.jsonl" 2> "$coverage_dir/build.log" || test_status=$?
python3 "$repo_dir/scripts/linux-coverage.py" "$coverage_dir" "$profile_dir" "$llvm_bin" "$test_status"
if [ "$test_status" -ne 0 ]; then
  tail -n 30 "$coverage_dir/build.log" >&2
  echo "Tests failed; see $coverage_dir/cargo.jsonl for test failures." >&2
fi
exit "$test_status"
