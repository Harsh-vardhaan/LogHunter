"""Centralized detection thresholds and correlation defaults."""

from datetime import timedelta

FAILED_AUTH_MEDIUM_THRESHOLD = 5
FAILED_AUTH_HIGH_THRESHOLD = 10
AUTH_SUCCESS_AFTER_FAILURE_THRESHOLD = 5
INVALID_USER_THRESHOLD = 3
AUTH_WINDOW_MINUTES = 10
AUTH_WINDOW = timedelta(minutes=AUTH_WINDOW_MINUTES)
WEB_4XX_THRESHOLD = 8
WEB_5XX_THRESHOLD = 5

SENSITIVE_PATHS = ("/.env", "/.git/", "/wp-admin", "/phpmyadmin", "/admin")
