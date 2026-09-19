import json
from pathlib import Path

from src.evidence_schema.example_records import (
    build_all_examples,
)
from src.evidence_schema.schema import (
    validate_evidence_record,
)


OUTPUT_PATH = Path(
    "docs/project-management/evidence/"
    "evidence_schema/example_records.json"
)


def main():

    records = build_all_examples()

    for record in records:
        validate_evidence_record(
            record
        )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            records,
            file,
            indent=2,
        )

    print(
        f"Exported {len(records)} "
        f"validated evidence records"
    )

    print(
        f"Output: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()