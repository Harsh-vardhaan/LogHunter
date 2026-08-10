"""Centralized Phase 2 rule thresholds."""

FAILED_AUTH_MEDIUM_THRESHOLD = 5
FAILED_AUTH_HIGH_THRESHOLD = 10
INVALID_USER_THRESHOLD = 3
WEB_4XX_THRESHOLD = 8
WEB_5XX_THRESHOLD = 5

SENSITIVE_PATHS = ("/.env", "/.git/", "/wp-admin", "/phpmyadmin", "/admin")
