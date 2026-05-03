# =============================================================================
# Консоль Windows: UTF-8 для stdout/stderr (меньше UnicodeEncodeError в PowerShell).
# =============================================================================
from __future__ import annotations

import sys
import warnings

_WARN_EMITTER_INSTALLED = False


def _install_safe_warning_emitter() -> None:
    """Сообщения warnings пишем с подстановкой, если stderr ещё в «узкой» кодировке."""
    global _WARN_EMITTER_INSTALLED
    if _WARN_EMITTER_INSTALLED:
        return
    def _showwarning(message, category, filename, lineno, file=None, line=None):  # type: ignore[no-untyped-def]
        if file is None:
            file = sys.stderr
        text = warnings.formatwarning(message, category, filename, lineno, line)
        try:
            file.write(text)
        except UnicodeEncodeError:
            safe_msg = str(message).encode("ascii", "replace").decode("ascii")
            file.write(warnings.formatwarning(safe_msg, category, filename, lineno, line))

    warnings.showwarning = _showwarning  # type: ignore[assignment]
    _WARN_EMITTER_INSTALLED = True


def configure_stdio_utf8() -> None:
    """Переключает stdout/stderr на UTF-8 с подстановкой несъедобных символов."""
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
            except (AttributeError, OSError, ValueError):
                continue
        _install_safe_warning_emitter()
