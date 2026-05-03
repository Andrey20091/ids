from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    from src.utils.console_encoding import configure_stdio_utf8

    configure_stdio_utf8()
    root = Path(__file__).resolve().parent
    app_path = root / "dashboard" / "app.py"
    from streamlit.web import bootstrap

    # Run Streamlit app in-process to avoid recursive self-launch in frozen EXE.
    bootstrap.run(
        main_script_path=str(app_path),
        is_hello=False,
        args=[],
        flag_options={},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
