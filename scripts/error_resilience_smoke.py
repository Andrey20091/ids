# =============================================================================
# Прогон типичных ошибочных сценариев (exit codes пайплайна).
# =============================================================================
"""
Проверяет, что команды при неверных входах завершаются с ожидаемым кодом.
Запуск из корня репозитория:
  python scripts/error_resilience_smoke.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _run(argv: list[str], expect_code: int | None = None) -> dict:
    """Subprocess: return metadata including returncode vs expect_code."""
    p = subprocess.run(
        [sys.executable, *argv],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    err = (p.stderr or "")[-2000:]
    out = (p.stdout or "")[-1000:]
    return {
        "argv": argv,
        "returncode": p.returncode,
        "expect_code": expect_code,
        "match": (expect_code is None or p.returncode == expect_code),
        "stderr_tail": err,
        "stdout_tail": out,
    }


def main() -> int:
    results: list[dict] = []

    # Missing input CSV → prepare exits 1
    results.append(
        _run(
            [
                "scripts/01_prepare_data.py",
                "--input",
                str(_ROOT / "data" / "raw" / "__no_such_file__cicids.csv"),
            ],
            expect_code=1,
        )
    )

    # Missing flows for detect → exit 1
    results.append(
        _run(
            [
                "scripts/03_run_detection_batch.py",
                "--data",
                str(_ROOT / "data" / "processed" / "__no_flows__.csv"),
            ],
            expect_code=1,
        )
    )

    # Missing train dataset → exit 1
    results.append(
        _run(
            [
                "scripts/02_train_all.py",
                "--data",
                str(_ROOT / "data" / "processed" / "__no_train__.csv"),
                "--skip-torch",
            ],
            expect_code=1,
        )
    )

    # Invalid main.py subcommand → argparse exit 2
    results.append(
        _run(
            ["main.py", "this_command_does_not_exist_12345"],
            expect_code=2,
        )
    )

    # check → 0 when core deps OK
    results.append(
        _run(
            ["main.py", "check"],
            expect_code=0,
        )
    )

    passed = sum(1 for r in results if r.get("match"))
    summary = {
        "scenarios": len(results),
        "expectation_matched": passed,
        "all_match": passed == len(results),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    for r in results:
        st = "OK" if r.get("match") else "MISMATCH"
        print(f"[{st}] code={r.get('returncode')} expect={r.get('expect_code')} argv={r.get('argv', [])[0:3]}")
    return 0 if summary["all_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
