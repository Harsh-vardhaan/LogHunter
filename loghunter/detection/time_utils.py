"""Reusable deterministic helpers for timestamp-aware correlation."""

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from ..models import LogEvent


def timestamped(events: Iterable[LogEvent]) -> list[LogEvent]:
    """Return timestamped events in chronological, stable order."""
    return sorted((event for event in events if event.timestamp is not None), key=lambda event: event.timestamp)


def group_by_source_and_username(events: Iterable[LogEvent]) -> dict[tuple[str, str | None], list[LogEvent]]:
    grouped: dict[tuple[str, str | None], list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.source_ip and event.timestamp is not None:
            grouped[(event.source_ip, event.username)].append(event)
    return {key: timestamped(value) for key, value in grouped.items()}


def first_threshold_window(events: Iterable[LogEvent], threshold: int, window: timedelta) -> list[LogEvent] | None:
    """Return the first chronological window reaching *threshold*, if any."""
    ordered = timestamped(events)
    start = 0
    for end, event in enumerate(ordered):
        while event.timestamp - ordered[start].timestamp > window:
            start += 1
        if end - start + 1 >= threshold:
            return ordered[start:end + 1]
    return None
