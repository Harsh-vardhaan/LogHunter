"""Safe, read-only loading of local text log files."""

from collections.abc import Iterator
from pathlib import Path


class LogLoadError(Exception):
    """A controlled error raised when a log cannot be loaded safely."""


def validate_log_file(file_path: str | Path) -> Path:
    path = Path(file_path)
    if not path.exists():
        raise LogLoadError(f"Log file does not exist: {path}")
    if path.is_symlink():
        raise LogLoadError(f"Symbolic-link log paths are not supported: {path}")
    if not path.is_file():
        raise LogLoadError(f"Log path is not a regular file: {path}")
    return path


def iter_log_lines(file_path: str | Path) -> Iterator[str]:
    """Yield decoded lines without loading the entire file into memory.

    Invalid UTF-8 bytes are replaced so one damaged line cannot terminate an
    otherwise useful analysis. The source file is opened read-only.
    """
    path = validate_log_file(file_path)
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline=None) as handle:
            for line in handle:
                yield line.rstrip("\r\n")
    except OSError as exc:
        raise LogLoadError(f"Unable to read log file '{path}': {exc}") from exc
