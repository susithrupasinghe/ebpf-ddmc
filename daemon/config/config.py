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

# Persisted live-tuned values (e.g. detection weights edited via the UI/API)
# survive daemon restarts here, layered on top of defaults.yaml automatically
# -- unlike --config, which must be passed explicitly.
_LOCAL_OVERRIDE_PATH = os.path.join(os.path.dirname(__file__), "local.yaml")


def load(path: str | None = None) -> dict:
    """Load and merge configuration: defaults -> local.yaml (if present) -> --config (if given)."""
    with open(_DEFAULTS_PATH, "r") as f:
        cfg = yaml.safe_load(f)

    if os.path.exists(_LOCAL_OVERRIDE_PATH):
        with open(_LOCAL_OVERRIDE_PATH, "r") as f:
            local_override = yaml.safe_load(f) or {}
        cfg = deep_merge(cfg, local_override)
        logger.info("Loaded local override from %s", _LOCAL_OVERRIDE_PATH)

    if path and os.path.exists(path):
        with open(path, "r") as f:
            override = yaml.safe_load(f) or {}
        cfg = deep_merge(cfg, override)
        logger.info("Loaded config from %s", path)

    return cfg


def save_local_override(section: str, values: dict):
    """
    Persist `values` under `section` into local.yaml, merged with any existing
    overrides. Used for live config changes (e.g. detection weights edited via
    the API/UI) so they survive a daemon restart without touching defaults.yaml.
    """
    existing = {}
    if os.path.exists(_LOCAL_OVERRIDE_PATH):
        with open(_LOCAL_OVERRIDE_PATH, "r") as f:
            existing = yaml.safe_load(f) or {}
    existing = deep_merge(existing, {section: values})
    with open(_LOCAL_OVERRIDE_PATH, "w") as f:
        yaml.safe_dump(existing, f, default_flow_style=False, sort_keys=False)


def deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result
