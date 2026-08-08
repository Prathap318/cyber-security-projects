"""Simple defensive SOC authentication log analyzer."""
from collections import Counter
from pathlib import Path
import re

LOG_FILE = Path(__file__).with_name("sample_auth.log")
FAILED_LOGIN = re.compile(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)")
THRESHOLD = 3


def analyze(path: Path) -> None:
    counts = Counter()
    if not path.exists():
        print(f"Log file not found: {path}")
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        match = FAILED_LOGIN.search(line)
        if match:
            counts[match.group(1)] += 1

    print("=== SOC Log Analyzer ===")
    if not counts:
        print("No failed SSH login attempts found.")
        return

    for ip, count in counts.most_common():
        status = "SUSPICIOUS" if count >= THRESHOLD else "Observed"
        print(f"{ip:15} failed_attempts={count:2}  {status}")


if __name__ == "__main__":
    analyze(LOG_FILE)
