#!/usr/bin/env python3
"""
Apply configuration fixes for common security misconfigurations.
Handles JSON, YAML, and environment file updates safely.
"""

import json
import argparse
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

try:
    import yaml
except ImportError:
    yaml = None


class ConfigFixer:
    def __init__(self, config_path: str, backup: bool = True):
        self.config_path = Path(config_path)
        self.backup = backup
        self.backup_path = None
        self._backup_created = False

        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

    def create_backup(self):
        """Create a timestamped backup of the config file (once per session)."""
        if not self.backup or self._backup_created:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_path = self.config_path.with_suffix(
            f"{self.config_path.suffix}.backup.{timestamp}"
        )
        shutil.copy2(self.config_path, self.backup_path)
        self._backup_created = True
        print(f"Backup created: {self.backup_path}")

    def load_config(self) -> Dict[str, Any]:
        """Load configuration file based on extension."""
        suffix = self.config_path.suffix.lower()

        if suffix == ".json":
            with open(self.config_path, 'r') as f:
                return json.load(f)
        elif suffix in [".yaml", ".yml"]:
            if yaml is None:
                raise ImportError(
                    "PyYAML is required for YAML config files. "
                    "Install with: pip install pyyaml"
                )
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        elif suffix == ".env":
            return self.parse_env_file()
        else:
            raise ValueError(f"Unsupported config format: {suffix}")

    def save_config(self, config: Dict[str, Any]):
        """Save configuration file based on extension."""
        suffix = self.config_path.suffix.lower()

        if suffix == ".json":
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
        elif suffix in [".yaml", ".yml"]:
            if yaml is None:
                raise ImportError(
                    "PyYAML is required for YAML config files. "
                    "Install with: pip install pyyaml"
                )
            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        elif suffix == ".env":
            self.write_env_file(config)
        else:
            raise ValueError(f"Unsupported config format: {suffix}")

    def parse_env_file(self) -> Dict[str, str]:
        """Parse .env file into dictionary."""
        config = {}
        with open(self.config_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
        return config

    def write_env_file(self, config: Dict[str, str]):
        """Write dictionary to .env file."""
        with open(self.config_path, 'w') as f:
            for key, value in config.items():
                f.write(f"{key}={value}\n")

    def apply_fix(self, path: str, value: Any, operation: str = "set") -> bool:
        """Apply a fix to the configuration.

        Args:
            path: Dot-notation path to the config value (e.g., "database.ssl.enabled")
            value: New value to set
            operation: "set" to set value, "delete" to remove key, "append" to add to array
        """
        try:
            self.create_backup()
            config = self.load_config()

            keys = path.split('.')
            current = config

            for key in keys[:-1]:
                if key not in current:
                    if operation == "delete":
                        print(f"Key not found: {path}")
                        return False
                    current[key] = {}
                current = current[key]

            final_key = keys[-1]

            if operation == "set":
                old_value = current.get(final_key, "N/A")
                current[final_key] = value
                print(f"Updated {path}: {old_value} -> {value}")

            elif operation == "delete":
                if final_key in current:
                    old_value = current[final_key]
                    del current[final_key]
                    print(f"Deleted {path} (was: {old_value})")
                else:
                    print(f"Key not found: {path}")
                    return False

            elif operation == "append":
                if final_key not in current:
                    current[final_key] = []
                if not isinstance(current[final_key], list):
                    print(f"Cannot append to non-list value at {path}")
                    return False
                current[final_key].append(value)
                print(f"Appended to {path}: {value}")

            self.save_config(config)
            return True

        except Exception as e:
            print(f"Failed to apply fix: {e}")
            if self.backup_path and self.backup_path.exists():
                print(f"   Restore from backup: {self.backup_path}")
            return False

    def apply_bulk_fixes(self, fixes: List[Dict[str, Any]]) -> int:
        """Apply multiple fixes from a list.

        Args:
            fixes: List of fix dictionaries with 'path', 'value', and optional 'operation'

        Returns:
            Number of successfully applied fixes
        """
        success_count = 0

        for fix in fixes:
            path = fix.get("path")
            value = fix.get("value")
            operation = fix.get("operation", "set")

            if not path:
                print(f"Skipping fix without path: {fix}")
                continue

            if self.apply_fix(path, value, operation):
                success_count += 1

        return success_count

    def restore_backup(self):
        """Restore from the most recent backup."""
        if not self.backup_path or not self.backup_path.exists():
            print("No backup found to restore")
            return False

        shutil.copy2(self.backup_path, self.config_path)
        print(f"Restored from backup: {self.backup_path}")
        return True


# Common security fixes
COMMON_FIXES = {
    "disable_debug": {
        "description": "Disable debug mode",
        "fixes": [
            {"path": "debug", "value": False},
            {"path": "DEBUG", "value": "false"},
        ]
    },
    "enable_https": {
        "description": "Enforce HTTPS",
        "fixes": [
            {"path": "server.ssl.enabled", "value": True},
            {"path": "force_https", "value": True},
        ]
    },
    "enable_csrf": {
        "description": "Enable CSRF protection",
        "fixes": [
            {"path": "security.csrf.enabled", "value": True},
            {"path": "csrf_protection", "value": True},
        ]
    },
    "secure_cookies": {
        "description": "Enable secure cookie flags",
        "fixes": [
            {"path": "session.cookie.secure", "value": True},
            {"path": "session.cookie.httpOnly", "value": True},
            {"path": "session.cookie.sameSite", "value": "Strict"},
        ]
    },
    "disable_cors_wildcard": {
        "description": "Disable CORS wildcard",
        "fixes": [
            {"path": "cors.allowedOrigins", "value": [], "operation": "set"},
        ]
    },
}


def main():
    parser = argparse.ArgumentParser(description="Apply configuration fixes for security issues")
    parser.add_argument("config_file", help="Path to configuration file")
    parser.add_argument("--path", help="Dot-notation path to config value (e.g., debug.enabled)")
    parser.add_argument("--value", help="New value to set")
    parser.add_argument("--operation", choices=["set", "delete", "append"], default="set", help="Operation to perform")
    parser.add_argument("--preset", choices=list(COMMON_FIXES.keys()), help="Apply common security fix preset")
    parser.add_argument("--bulk", help="Path to JSON file with bulk fixes")
    parser.add_argument("--no-backup", action="store_true", help="Skip creating backup")
    parser.add_argument("--restore", action="store_true", help="Restore from most recent backup")
    parser.add_argument("--list-presets", action="store_true", help="List available fix presets")

    args = parser.parse_args()

    if args.list_presets:
        print("Available security fix presets:\n")
        for name, preset in COMMON_FIXES.items():
            print(f"  {name}")
            print(f"    {preset['description']}")
            for fix in preset['fixes']:
                print(f"      - {fix['path']} = {fix['value']}")
            print()
        return

    try:
        fixer = ConfigFixer(args.config_file, backup=not args.no_backup)

        if args.restore:
            fixer.restore_backup()
            return

        if args.preset:
            print(f"Applying preset: {args.preset}")
            preset = COMMON_FIXES[args.preset]
            success = fixer.apply_bulk_fixes(preset["fixes"])
            print(f"\nApplied {success}/{len(preset['fixes'])} fixes")

        elif args.bulk:
            with open(args.bulk, 'r') as f:
                fixes = json.load(f)
            success = fixer.apply_bulk_fixes(fixes)
            print(f"\nApplied {success}/{len(fixes)} fixes")

        elif args.path:
            if args.value is None and args.operation != "delete":
                print("--value required for set/append operations")
                return

            value = args.value
            if value and args.operation != "delete":
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass  # Use as string

            fixer.apply_fix(args.path, value, args.operation)

        else:
            print("Must specify --path, --preset, or --bulk")
            parser.print_help()

    except Exception as e:
        print(f"Error: {e}")
        import sys
        sys.exit(1)


if __name__ == "__main__":
    main()
