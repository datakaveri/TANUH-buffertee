"""Minimal config loader for the Buffer TEE."""

import os
import warnings
import yaml
from pathlib import Path


class _NS:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class Config:
    def __init__(self):
        base_dir   = os.getenv("BASE_DIR", str(Path(__file__).parent.parent))
        config_yml = Path(base_dir) / "config.yml"

        if not config_yml.exists():
            warnings.warn(f"config.yml not found at {config_yml}, using defaults")
            raw = {}
        else:
            with open(config_yml) as f:
                raw = yaml.safe_load(f) or {}

        def expand(obj):
            if isinstance(obj, dict):
                return {k: expand(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [expand(i) for i in obj]
            if isinstance(obj, str):
                return obj.replace("${BASE_DIR}", base_dir)
            return obj

        raw = expand(raw)

        self._base_dir = base_dir

        paths_cfg   = raw.get("paths", {})
        service_cfg = raw.get("service", {"port": 4100, "host": "0.0.0.0"})
        cors_cfg    = raw.get("cors", {})

        self.paths   = _NS(**paths_cfg)
        self.service = _NS(**service_cfg)
        self.cors    = _NS(
            origins=cors_cfg.get("origins", ["*"]),
            methods=cors_cfg.get("methods", ["GET", "POST", "OPTIONS"]),
            allow_headers=cors_cfg.get("allow_headers", ["Content-Type"]),
            expose_headers=cors_cfg.get("expose_headers", ["Content-Type"]),
            supports_credentials=cors_cfg.get("supports_credentials", False),
            max_age=cors_cfg.get("max_age", 3600),
        )

    @property
    def base_dir(self):
        return self._base_dir


config = Config()
