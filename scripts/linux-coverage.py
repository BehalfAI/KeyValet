#!/usr/bin/env python3
"""Export native LLVM coverage and summarize the Linux security implementation."""
import json
from pathlib import Path
import subprocess
import sys


SOURCES = (
    "kv-platform/src/linux.rs",
    "kv-platform/src/peer_linux.rs",
    "kv-helper/src/daemon_linux.rs",
    "kv-cli/src/linux_cli.rs",
    "kv-vault/src/master_key.rs",
)


def summarize(lcov):
    files = {}
    for record in lcov.split("end_of_record"):
        lines = record.strip().splitlines()
        filename = next((line[3:] for line in lines if line.startswith("SF:")), "")
        name = next((name for name in SOURCES if filename.endswith("/crates/" + name)), None)
        if name is None:
            continue
        # Unit tests live in separate module files, so none of their lines or
        # fixtures enter this production-file summary.
        counts = [
            int(line.split(",")[1])
            for line in lines
            if line.startswith("DA:")
        ]
        if not counts:
            raise RuntimeError("No production-line counters for: " + name)
        covered = sum(count > 0 for count in counts)
        files[name] = {
            "covered": covered,
            "lines": len(counts),
            "percent": round(100 * covered / len(counts), 2) if counts else 0,
        }
    missing = set(SOURCES) - files.keys()
    if missing:
        raise RuntimeError("Coverage did not contain: " + ", ".join(sorted(missing)))
    return files


def main():
    report, profiles, llvm = map(Path, sys.argv[1:4])
    test_status = int(sys.argv[4])
    raw_profiles = sorted(str(path) for path in profiles.glob("*.profraw"))
    if not raw_profiles:
        raise RuntimeError("No profiles were written; see build.log")
    data = report / "coverage.profdata"
    subprocess.run(
        [str(llvm / "llvm-profdata"), "merge", "-sparse", *raw_profiles, "-o", str(data)],
        check=True,
    )
    binaries = set()
    for line in (report / "cargo.jsonl").read_text().splitlines():
        try:
            artifact = json.loads(line)
        except ValueError:
            continue
        if (
            artifact.get("reason") == "compiler-artifact"
            and artifact["profile"]["test"]
            and artifact.get("executable")
        ):
            binaries.add(artifact["executable"])
    binaries = sorted(binaries)
    if not binaries:
        raise RuntimeError("No test executables were built; see build.log")
    command = [str(llvm / "llvm-cov"), "export", "-format=lcov", "-instr-profile=" + str(data), binaries[0]]
    for binary in binaries[1:]:
        command.extend(["-object", binary])
    with (report / "lcov.info").open("w") as output:
        subprocess.run(command, stdout=output, check=True)
    files = summarize((report / "lcov.info").read_text())
    covered = sum(file["covered"] for file in files.values())
    total = sum(file["lines"] for file in files.values())
    result = {
        "scope": "Linux security modules and shared master-key metadata; production lines only",
        "test_exit_code": test_status,
        "files": files,
        "total": {"covered": covered, "lines": total, "percent": round(100 * covered / total, 2)},
    }
    (report / "coverage.json").write_text(json.dumps(result, indent=2) + "\n")
    rows = ["| Source | Covered production lines | Coverage |", "| --- | ---: | ---: |"]
    for name in SOURCES:
        file = files[name]
        rows.append(f"| `{name}` | {file['covered']}/{file['lines']} | {file['percent']:.2f}% |")
    rows.extend(["", result["scope"] + ".", f"Test exit code: {test_status}.", ""])
    summary = "\n".join(rows)
    (report / "summary.md").write_text(summary)
    print(summary, end="")
    gaps = [name for name, file in files.items() if file["covered"] != file["lines"]]
    if gaps:
        raise SystemExit("Production line coverage must be 100% for every module: " + ", ".join(gaps))


if __name__ == "__main__":
    main()
