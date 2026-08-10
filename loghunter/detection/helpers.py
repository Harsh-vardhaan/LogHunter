"""Small deterministic grouping helpers shared by detection rules."""

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime

from ..models import LogEvent


def group_by_source(events: Iterable[LogEvent]) -> dict[str, list[LogEvent]]:
    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.source_ip:
            grouped[event.source_ip].append(event)
    return dict(grouped)


def dominant_username(events: Iterable[LogEvent]) -> str | None:
    counts = Counter(event.username for event in events if event.username)
    if not counts:
        return None
    ordered = counts.most_common()
    return ordered[0][0] if len(ordered) == 1 or ordered[0][1] > ordered[1][1] else None


def event_range(events: list[LogEvent]) -> tuple[datetime | None, datetime | None]:
    timestamps = [event.timestamp for event in events if event.timestamp]
    return (min(timestamps), max(timestamps)) if timestamps else (None, None)


def source_files(events: Iterable[LogEvent]) -> tuple[str, ...]:
    """Return concise, deterministic source context for a finding."""
    files: set[str] = set()
    for event in events:
        files.update(event.source_files)
        if event.source_file:
            files.add(event.source_file)
    return tuple(sorted(files))
