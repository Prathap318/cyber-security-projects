"""Simple SHA-256 file integrity monitoring demonstration."""
from hashlib import sha256
from pathlib import Path
import json

BASE_DIR = Path(__file__).with_name("monitored_files")
BASE_DIR.mkdir(exist_ok=True)
BASELINE = Path(__file__).with_name("baseline.json")


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot() -> dict[str, str]:
    return {
        str(path.relative_to(BASE_DIR)): sha256_file(path)
        for path in BASE_DIR.rglob("*")
        if path.is_file()
    }


def main() -> None:
    current = snapshot()
    if not BASELINE.exists():
        BASELINE.write_text(json.dumps(current, indent=2), encoding="utf-8")
        print("Baseline created. Run the monitor again after making changes.")
        return

    previous = json.loads(BASELINE.read_text(encoding="utf-8"))
    added = sorted(set(current) - set(previous))
    removed = sorted(set(previous) - set(current))
    modified = sorted(name for name in current if name in previous and current[name] != previous[name])

    print("=== File Integrity Monitor ===")
    for name in added:
        print(f"ADDED:    {name}")
    for name in modified:
        print(f"MODIFIED: {name}")
    for name in removed:
        print(f"DELETED:  {name}")
    if not (added or modified or removed):
        print("No integrity changes detected.")


if __name__ == "__main__":
    main()
