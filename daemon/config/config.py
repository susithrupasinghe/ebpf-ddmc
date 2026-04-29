"""
EDDMC - Configuration Loader

Merges defaults.yaml with an optional user-supplied config file.
Provides typed access to all config values.
"""

import os
import yaml
import logging

logger = logging.getLogger("eddmc.config")

_DEFAULTS_PATH = os.path.join(os.path.dirname(__file__), "defaults.yaml")


def load(path: str | None = None) -> dict:
    """Load and merge configuration from defaults + optional override file."""
    with open(_DEFAULTS_PATH, "r") as f:
        cfg = yaml.safe_load(f)

    if path and os.path.exists(path):
        with open(path, "r") as f:
            override = yaml.safe_load(f) or {}
        cfg = _deep_merge(cfg, override)
        logger.info("Loaded config from %s", path)

    return cfg


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
