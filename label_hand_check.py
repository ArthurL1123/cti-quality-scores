"""
Hand-label the filter sample one indicator at a time.

Reads output/hand_check_sample.csv, shows each unlabelled row, and saves your
answer straight back to the file, so you can stop and resume at any time.
The filter_matched_on column is never shown, so it cannot bias the judgement.

Usage:
    python label_hand_check.py
"""
import csv
import re
import sys
import textwrap
from pathlib import Path

CSV_PATH  = Path("output/hand_check_sample.csv")
LABEL_COL = "healthcare_relevant (yes/no/unclear)"
ANSWERS   = {"y": "yes", "n": "no", "u": "unclear"}

# Words highlighted to make scanning faster. Highlighting only; you decide.
HIGHLIGHT = re.compile(
    r"(health\w*|hospital\w*|medical|medicine|pharma\w*|patient\w*|clinic\w*|"
    r"biotech\w*|insurance|insurer\w*)",
    re.IGNORECASE,
)


def highlight(text: str) -> str:
    return HIGHLIGHT.sub(lambda m: f">>{m.group(0).upper()}<<", text)


def wrap(label: str, text: str) -> None:
    text = text or "(none)"
    lines = textwrap.wrap(highlight(text), width=100) or ["(none)"]
    print(f"  {label:<12}{lines[0]}")
    for line in lines[1:]:
        print(f"  {'':<12}{line}")


def save(rows: list[dict], fieldnames: list[str]) -> None:
    with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    if not CSV_PATH.exists():
        print(f"Not found: {CSV_PATH}")
        return 1

    with open(CSV_PATH, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    todo = [r for r in rows if not r[LABEL_COL].strip()]
    print(f"{len(rows) - len(todo)} of {len(rows)} already labelled. "
          f"Keys: y = yes, n = no, u = unclear, q = save and quit.\n")

    for row in todo:
        print("=" * 112)
        print(f"  #{row['no']} of {len(rows)}   source: {row['source']}   type: {row['type']}")
        wrap("value:", row["value"])
        wrap("labels:", row["labels"])
        wrap("report:", row["report_name"])
        wrap("summary:", row["report_description"])

        while True:
            answer = input("\n  Healthcare relevant? [y/n/u/q] ").strip().lower()
            if answer in ANSWERS or answer == "q":
                break
            print("  Please type y, n, u or q.")

        if answer == "q":
            break

        row[LABEL_COL] = ANSWERS[answer]
        row["note"] = input("  Note (Enter to skip): ").strip()
        save(rows, fieldnames)

    done = [r[LABEL_COL] for r in rows if r[LABEL_COL].strip()]
    print(f"\nSaved. Labelled {len(done)} of {len(rows)}: "
          f"yes={done.count('yes')} no={done.count('no')} unclear={done.count('unclear')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
