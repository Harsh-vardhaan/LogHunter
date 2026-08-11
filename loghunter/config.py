"""Immutable detection configuration and strict local JSON loading."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .loader import LogLoadError, validate_log_file

CONFIG_SCHEMA_VERSION = "1.0"
MIN_THRESHOLD = 1
MAX_THRESHOLD = 100_000
MIN_WINDOW_MINUTES = 1
MAX_WINDOW_MINUTES = 1_440


class ConfigError(Exception):
    """Controlled configuration loading or validation error."""


@dataclass(frozen=True, slots=True)
class AuthDetectionConfig:
    failed_medium_threshold: int = 5
    failed_high_threshold: int = 10
    invalid_user_threshold: int = 3
    success_after_failure_threshold: int = 5
    window_minutes: int = 10


@dataclass(frozen=True, slots=True)
class WebDetectionConfig:
    client_error_threshold: int = 8
    server_error_threshold: int = 5


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    version: str = CONFIG_SCHEMA_VERSION
    auth: AuthDetectionConfig = AuthDetectionConfig()
    web: WebDetectionConfig = WebDetectionConfig()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    config: DetectionConfig
    source: str = "default"


DEFAULT_CONFIG = DetectionConfig()
DEFAULT_LOADED_CONFIG = LoadedConfig(DEFAULT_CONFIG)

_TOP_LEVEL_KEYS = frozenset(("version", "auth", "web"))
_AUTH_KEYS = frozenset(AuthDetectionConfig.__dataclass_fields__)
_WEB_KEYS = frozenset(WebDetectionConfig.__dataclass_fields__)


def _require_exact_keys(data: dict[str, Any], expected: frozenset[str], location: str) -> None:
    unknown = set(data) - expected
    missing = expected - set(data)
    if unknown:
        raise ConfigError(f"Unknown {location} key(s): {', '.join(sorted(unknown))}")
    if missing:
        raise ConfigError(f"Missing required {location} key(s): {', '.join(sorted(missing))}")


def _bounded_integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def parse_config(data: object) -> DetectionConfig:
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a JSON object")
    _require_exact_keys(data, _TOP_LEVEL_KEYS, "top-level")
    if data["version"] != CONFIG_SCHEMA_VERSION:
        raise ConfigError(f"Unsupported configuration version: {data['version']!r}")
    if not isinstance(data["auth"], dict):
        raise ConfigError("auth must be a JSON object")
    if not isinstance(data["web"], dict):
        raise ConfigError("web must be a JSON object")
    _require_exact_keys(data["auth"], _AUTH_KEYS, "auth")
    _require_exact_keys(data["web"], _WEB_KEYS, "web")

    auth_values = {
        key: _bounded_integer(
            value, f"auth.{key}",
            MIN_WINDOW_MINUTES if key == "window_minutes" else MIN_THRESHOLD,
            MAX_WINDOW_MINUTES if key == "window_minutes" else MAX_THRESHOLD,
        )
        for key, value in data["auth"].items()
    }
    if auth_values["failed_high_threshold"] < auth_values["failed_medium_threshold"]:
        raise ConfigError("auth.failed_high_threshold must be greater than or equal to auth.failed_medium_threshold")
    web_values = {
        key: _bounded_integer(value, f"web.{key}", MIN_THRESHOLD, MAX_THRESHOLD)
        for key, value in data["web"].items()
    }
    return DetectionConfig(
        version=CONFIG_SCHEMA_VERSION,
        auth=AuthDetectionConfig(**auth_values),
        web=WebDetectionConfig(**web_values),
    )


def load_config(file_path: str | None = None) -> LoadedConfig:
    if file_path is None:
        return DEFAULT_LOADED_CONFIG
    try:
        path = validate_log_file(file_path)
    except LogLoadError as exc:
        raise ConfigError(str(exc).replace("Log file", "Configuration file").replace("Log path", "Configuration path")) from exc
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Malformed JSON in configuration '{file_path}': {exc.msg} at line {exc.lineno}, column {exc.colno}") from exc
    except OSError as exc:
        raise ConfigError(f"Unable to read configuration '{file_path}': {exc}") from exc
    return LoadedConfig(parse_config(data), file_path)
