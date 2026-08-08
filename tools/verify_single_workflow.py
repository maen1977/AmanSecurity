from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
workflow_dir = root / ".github" / "workflows"
files = sorted(
    p.relative_to(root).as_posix()
    for p in workflow_dir.glob("*")
    if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
)
expected = [".github/workflows/main.yml"]
if files != expected:
    print("SINGLE_WORKFLOW_GATE_FAILED")
    print("Expected exactly:", expected[0])
    print("Found:")
    for item in files:
        print(" -", item)
    sys.exit(1)
print("SINGLE_WORKFLOW_GATE_OK count=1 file=.github/workflows/main.yml trigger=manual")
