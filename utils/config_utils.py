#!/usr/bin/env python3
"""Configuration loading and management utilities for bug bounty hunting tools.

Provides JSON config loading with error handling, environment variable
configuration (prefixed), deep merge, dot-path key access, schema
validation, a ConfigManager class for lifecycle management, and CLI
argument generation.
"""

import json
import os
import copy
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_DIR = "config"
DEFAULT_CONFIG_FILE = "hercules.json"
HOME_DIR = Path.home()
PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised when a configuration operation fails."""
    pass


class ConfigValidationError(ConfigError):
    """Raised when configuration fails schema validation."""
    pass


class ConfigNotFoundError(ConfigError):
    """Raised when a configuration file or path is not found."""
    pass


# ---------------------------------------------------------------------------
# JSON config loading
# ---------------------------------------------------------------------------

def load_json_config(path: Union[str, Path]) -> Dict[str, Any]:
    """Load a JSON configuration file with error handling.

    Reads and parses a JSON file, providing descriptive error messages
    for common failure modes (file not found, parse error, etc.).

    Args:
        path: Path to the JSON config file (string or Path).

    Returns:
        Parsed dictionary from the JSON file.

    Raises:
        ConfigNotFoundError: If the file does not exist.
        ConfigError: If the file cannot be parsed or is not a dict.

    Example:
        >>> cfg = load_json_config("config/hercules.json")
    """
    path = Path(path).resolve()

    if not path.exists():
        raise ConfigNotFoundError(
            f"Configuration file not found: {path}"
        )

    if not path.is_file():
        raise ConfigNotFoundError(
            f"Configuration path is not a file: {path}"
        )

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"Failed to parse JSON config at {path}: {exc}"
        ) from exc
    except PermissionError as exc:
        raise ConfigError(
            f"Permission denied reading config: {path}"
        ) from exc
    except OSError as exc:
        raise ConfigError(
            f"OS error reading config at {path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ConfigError(
            f"Config file must contain a JSON object (dict), got {type(data).__name__}"
        )

    return data


# ---------------------------------------------------------------------------
# Environment variable config loading
# ---------------------------------------------------------------------------

def _parse_env_value(value: str) -> Any:
    """Parse an environment variable string into a Python type.

    Attempts to interpret the value as JSON (for complex types),
    then falls back to int, float, bool, or str.

    Args:
        value: The raw environment variable string.

    Returns:
        Parsed Python value.
    """
    # Try JSON first (handles dicts, lists, numbers, booleans, nulls)
    try:
        return json.loads(value)
    except (json.JSONDecodeError, ValueError):
        pass

    # Boolean strings
    lower = value.lower().strip()
    if lower in ("true", "yes", "1"):
        return True
    if lower in ("false", "no", "0"):
        return False

    # Integer
    try:
        return int(value)
    except ValueError:
        pass

    # Float
    try:
        return float(value)
    except ValueError:
        pass

    # Fall back to string
    return value


def load_env_config(
    prefix: str = "HERCULES_",
    *,
    source: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Load configuration from environment variables with a given prefix.

    Supports nested keys using double-underscore separators.
    Example: ``HERCULES_TARGET_DOMAIN=example.com`` becomes
    ``{"target": {"domain": "example.com"}}``.

    Args:
        prefix: Environment variable prefix (default 'HERCULES_',
            case-sensitive). Only variables starting with this
            prefix are loaded. The prefix is stripped from keys.
        source: Optional dict to use instead of ``os.environ``
            (for testing). Defaults to ``os.environ``.

    Returns:
        Nested config dictionary built from env vars.

    Example:
        >>> import os
        >>> os.environ["HERCULES_TARGET_DOMAIN"] = "example.com"
        >>> load_env_config()
        {'target': {'domain': 'example.com'}}
    """
    if source is None:
        source = os.environ

    config: Dict[str, Any] = {}
    prefix_len = len(prefix)

    for raw_key, raw_value in source.items():
        if not raw_key.startswith(prefix):
            continue

        key_part = raw_key[prefix_len:]
        if not key_part:
            continue

        parts = key_part.lower().split("__")
        parsed_value = _parse_env_value(raw_value)

        current = config
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                current[part] = parsed_value
            else:
                if part not in current:
                    current[part] = {}
                elif not isinstance(current[part], dict):
                    current[part] = {}
                current = current[part]

    return config


# ---------------------------------------------------------------------------
# Config merge utilities
# ---------------------------------------------------------------------------

def merge_configs(
    base: Dict[str, Any], override: Dict[str, Any]
) -> Dict[str, Any]:
    """Deep merge two configuration dictionaries.

    Performs a recursive merge where values from ``override`` take
    precedence over ``base``. Lists are replaced, not concatenated.
    The original dicts are not modified.

    Args:
        base: Base configuration dictionary.
        override: Override configuration dictionary (higher priority).

    Returns:
        New merged dictionary.

    Example:
        >>> merge_configs({"a": 1, "b": {"c": 2}}, {"b": {"d": 3}})
        {'a': 1, 'b': {'c': 2, 'd': 3}}
    """
    result = copy.deepcopy(base)

    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = copy.deepcopy(value)

    return result


def _get_nested(
    config: Dict[str, Any], key_path: str, default: Any = None
) -> Tuple[Any, bool]:
    """Internal helper to get a nested value by dot-separated path.

    Args:
        config: The config dictionary.
        key_path: Dot-separated path (e.g., 'target.domain').
        default: Fallback if path not found.

    Returns:
        Tuple of (value, found) where found is True if the full path
        exists in the config.
    """
    if not key_path:
        return config, True

    parts = key_path.split(".")
    current: Any = config

    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default, False

    return current, True


def get_config_value(
    config: Dict[str, Any],
    key_path: str,
    default: Any = None,
) -> Any:
    """Get a nested configuration value via dot-separated path.

    Args:
        config: The configuration dictionary.
        key_path: Dot-separated path (e.g., 'target.port').
        default: Value to return if the path is not found.

    Returns:
        The value at key_path, or default if not found.

    Example:
        >>> cfg = {"target": {"domain": "example.com", "port": 443}}
        >>> get_config_value(cfg, "target.domain")
        'example.com'
        >>> get_config_value(cfg, "target.missing", "fallback")
        'fallback'
    """
    value, _ = _get_nested(config, key_path, default)
    return value


def set_config_value(
    config: Dict[str, Any],
    key_path: str,
    value: Any,
) -> Dict[str, Any]:
    """Set a nested configuration value via dot-separated path.

    Creates intermediate dicts as needed. Modifies the input dict in place
    and also returns it for convenience.

    Args:
        config: The configuration dictionary (modified in place).
        key_path: Dot-separated path (e.g., 'target.port').
        value: The value to set.

    Returns:
        The modified config dictionary.

    Example:
        >>> cfg = {}
        >>> set_config_value(cfg, "target.port", 443)
        {'target': {'port': 443}}
    """
    if not key_path:
        raise ValueError("key_path must not be empty")

    parts = key_path.split(".")
    current = config

    for i, part in enumerate(parts):
        if i == len(parts) - 1:
            current[part] = value
        else:
            if part not in current:
                current[part] = {}
            elif not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]

    return config


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def _validate_type(value: Any, expected_type: Any, path: str) -> List[str]:
    """Validate a single value against a type spec from the schema.

    Args:
        value: The value to validate.
        expected_type: Type (e.g., str, int) or list of valid types.
        path: Dot-separated path for error messages.

    Returns:
        List of error messages (empty if valid).
    """
    errors: List[str] = []

    if isinstance(expected_type, type):
        if not isinstance(value, expected_type):
            errors.append(
                f"{path}: expected {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )
    elif isinstance(expected_type, (list, tuple)):
        if not any(isinstance(value, t) for t in expected_type):
            type_names = [t.__name__ for t in expected_type]
            errors.append(
                f"{path}: expected one of ({', '.join(type_names)}), "
                f"got {type(value).__name__}"
            )
    elif isinstance(expected_type, dict):
        if not isinstance(value, dict):
            errors.append(
                f"{path}: expected dict, got {type(value).__name__}"
            )
        else:
            sub_errors = _validate_schema(
                value, expected_type, prefix=path
            )
            errors.extend(sub_errors)
    elif callable(expected_type):
        try:
            result = expected_type(value)
            if result is not True:
                errors.append(f"{path}: custom validation failed: {result}")
        except Exception as exc:
            errors.append(f"{path}: custom validation raised: {exc}")

    return errors


def _validate_schema(
    config: Dict[str, Any],
    schema: Dict[str, Any],
    prefix: str = "",
) -> List[str]:
    """Recursively validate config against a schema dict.

    Args:
        config: Config dict to validate.
        schema: Schema dict mapping key paths to type specs.
        prefix: Dot-separated path prefix for error messages.

    Returns:
        List of validation error strings.
    """
    errors: List[str] = []

    for key, expected_type in schema.items():
        path = f"{prefix}.{key}" if prefix else key

        if key not in config:
            errors.append(f"{path}: missing required key")
            continue

        value = config[key]
        sub_errors = _validate_type(value, expected_type, path)
        errors.extend(sub_errors)

    return errors


def validate_config(
    config: Dict[str, Any],
    schema: Dict[str, Any],
) -> List[str]:
    """Validate a configuration dictionary against a schema.

    The schema defines expected types for each key. Keys not in the
    schema are ignored (allows for optional/extensible fields).

    Args:
        config: The configuration dictionary to validate.
        schema: Schema dict mapping key names to type specs.
            Type specs can be:
            - A Python type (``str``, ``int``, ``list``, etc.)
            - A tuple/list of types (``(str, int)``)
            - A nested dict for sub-schemas
            - A callable that returns True or an error str

    Returns:
        List of validation error messages. Empty list if valid.

    Example:
        >>> schema = {"target": {"domain": str, "port": int}}
        >>> cfg = {"target": {"domain": "example.com", "port": 443}}
        >>> validate_config(cfg, schema)
        []
        >>> validate_config({"target": {"port": "bad"}}, schema)
        ["target.domain: missing required key", "target.port: expected int, got str"]
    """
    if not isinstance(config, dict):
        return ["Config must be a dictionary"]

    if not isinstance(schema, dict):
        return ["Schema must be a dictionary"]

    return _validate_schema(config, schema)


# ---------------------------------------------------------------------------
# ConfigManager class
# ---------------------------------------------------------------------------

class ConfigManager:
    """Configuration lifecycle manager.

    Handles loading configs from multiple sources (defaults, files,
    environment variables, overrides), merging them in priority order,
    and providing typed access to values. Supports layering and
    reloading.

    Priority order (highest to lowest):
    1. Override dict
    2. Additional config files
    3. Environment variables
    4. Primary config file
    5. Defaults provided at construction

    Attributes:
        config: The merged configuration dictionary.
        loaded_files: List of config file paths that were loaded.
    """

    def __init__(
        self,
        defaults: Optional[Dict[str, Any]] = None,
        config_path: Optional[Union[str, Path]] = None,
        env_prefix: str = "HERCULES_",
        auto_load_env: bool = True,
    ):
        """Initialize the ConfigManager.

        Args:
            defaults: Default configuration values (lowest priority).
            config_path: Path to a primary JSON config file.
            env_prefix: Prefix for environment variable config.
            auto_load_env: If True, load env vars immediately.
        """
        self._defaults: Dict[str, Any] = copy.deepcopy(defaults or {})
        self._config_path: Optional[Path] = None
        self._env_prefix: str = env_prefix
        self._env_config: Dict[str, Any] = {}
        self._file_config: Dict[str, Any] = {}
        self._override_config: Dict[str, Any] = {}
        self._additional_files: Dict[str, Dict[str, Any]] = {}

        self.config: Dict[str, Any] = copy.deepcopy(self._defaults)
        self.loaded_files: List[str] = []

        if config_path is not None:
            self.load_config_file(
                resolve_config_path(config_path)
            )

        if auto_load_env:
            self.load_env_config()

    def load_config_file(
        self, path: Union[str, Path]
    ) -> "ConfigManager":
        """Load a JSON config file and merge it into current config.

        Args:
            path: Path to the JSON config file.

        Returns:
            Self for method chaining.

        Raises:
            ConfigNotFoundError: If the file does not exist.
            ConfigError: If parsing fails.
        """
        resolved = resolve_config_path(path)
        file_config = load_json_config(resolved)
        self._file_config = merge_configs(
            self._file_config, file_config
        )
        self.loaded_files.append(str(resolved))
        self._rebuild()
        return self

    def load_env_config(
        self, prefix: Optional[str] = None
    ) -> "ConfigManager":
        """Load configuration from environment variables.

        Args:
            prefix: Optional override for env prefix. Uses the prefix
                set at construction if not provided.

        Returns:
            Self for method chaining.
        """
        effective_prefix = (
            prefix if prefix is not None else self._env_prefix
        )
        self._env_config = load_env_config(effective_prefix)
        self._rebuild()
        return self

    def apply_overrides(
        self, overrides: Dict[str, Any]
    ) -> "ConfigManager":
        """Apply an override config dict (highest priority).

        Args:
            overrides: Dict of overrides to apply.

        Returns:
            Self for method chaining.
        """
        self._override_config = merge_configs(
            self._override_config, overrides
        )
        self._rebuild()
        return self

    def load_additional_file(
        self, path: Union[str, Path]
    ) -> "ConfigManager":
        """Load an additional config file (between env and overrides).

        Additional files are merged after environment variables but
        before overrides. Later files override earlier ones.

        Args:
            path: Path to the additional JSON config file.

        Returns:
            Self for method chaining.
        """
        resolved = resolve_config_path(path)
        file_config = load_json_config(resolved)
        self._additional_files[str(resolved)] = file_config
        self.loaded_files.append(str(resolved))
        self._rebuild()
        return self

    def reload(self) -> "ConfigManager":
        """Reload all previously loaded config files.

        Useful when config files may have changed on disk.

        Returns:
            Self for method chaining.
        """
        loaded = list(self.loaded_files)
        self.loaded_files.clear()
        self._file_config = {}
        self._additional_files = {}

        if self._config_path is not None:
            self.load_config_file(self._config_path)

        for file_path in loaded:
            if file_path != str(self._config_path):
                self.load_additional_file(file_path)

        return self

    def _rebuild(self) -> None:
        """Rebuild the merged config from all layers."""
        config = copy.deepcopy(self._defaults)
        config = merge_configs(config, self._file_config)
        config = merge_configs(config, self._env_config)

        for additional in self._additional_files.values():
            config = merge_configs(config, additional)

        config = merge_configs(config, self._override_config)
        self.config = config

    def get(
        self,
        key_path: str,
        default: Any = None,
    ) -> Any:
        """Get a configuration value by dot-separated key path.

        Args:
            key_path: Dot-separated path (e.g., 'target.port').
            default: Default if path not found.

        Returns:
            The config value at key_path, or default.
        """
        return get_config_value(self.config, key_path, default)

    def set(
        self, key_path: str, value: Any
    ) -> "ConfigManager":
        """Set a configuration value by dot-separated key path.

        Args:
            key_path: Dot-separated path.
            value: Value to set.

        Returns:
            Self for method chaining.
        """
        set_config_value(self.config, key_path, value)
        return self

    def validate(
        self, schema: Dict[str, Any]
    ) -> List[str]:
        """Validate the current config against a schema.

        Args:
            schema: Schema dict (see ``validate_config``).

        Returns:
            List of validation errors (empty if valid).
        """
        return validate_config(self.config, schema)

    def to_dict(self) -> Dict[str, Any]:
        """Return a deep copy of the current merged config.

        Returns:
            Deep copy of self.config.
        """
        return copy.deepcopy(self.config)

    def get_string(
        self, key_path: str, default: str = ""
    ) -> str:
        """Get a config value as string.

        Args:
            key_path: Dot-separated path.
            default: Default string.

        Returns:
            String value.
        """
        value = self.get(key_path, default)
        if not isinstance(value, str):
            return str(value)
        return value

    def get_int(
        self, key_path: str, default: int = 0
    ) -> int:
        """Get a config value as int.

        Args:
            key_path: Dot-separated path.
            default: Default int.

        Returns:
            Integer value.
        """
        value = self.get(key_path, default)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def get_bool(
        self, key_path: str, default: bool = False
    ) -> bool:
        """Get a config value as bool.

        Args:
            key_path: Dot-separated path.
            default: Default bool.

        Returns:
            Boolean value.
        """
        value = self.get(key_path, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1")
        if isinstance(value, (int, float)):
            return value != 0
        return bool(value) if value is not None else default

    def get_list(
        self, key_path: str, default: Optional[List[Any]] = None
    ) -> List[Any]:
        """Get a config value as list.

        Args:
            key_path: Dot-separated path.
            default: Default list.

        Returns:
            List value.
        """
        value = self.get(key_path, default or [])
        if not isinstance(value, list):
            return [value] if value is not None else []
        return value

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}"
            f"(files={self.loaded_files}, "
            f"keys={len(self.config)})"
        )


# ---------------------------------------------------------------------------
# Config saving
# ---------------------------------------------------------------------------

def save_config(
    config: Dict[str, Any],
    path: Union[str, Path],
    *,
    indent: int = 2,
    sort_keys: bool = True,
    ensure_ascii: bool = False,
) -> Path:
    """Save a configuration dictionary to a JSON file.

    Args:
        config: The configuration dict to save.
        path: Output file path.
        indent: JSON indentation level (default 2).
        sort_keys: Whether to sort keys alphabetically (default True).
        ensure_ascii: Whether to escape non-ASCII characters (default False).

    Returns:
        The resolved path where the file was saved.

    Raises:
        ConfigError: If the file cannot be written.

    Example:
        >>> save_config({"target": {"domain": "example.com"}}, "config.json")
        WindowsPath('C:/.../config.json')
    """
    path = Path(path).resolve()

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(
            f"Failed to create config directory {path.parent}: {exc}"
        ) from exc

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                config,
                f,
                indent=indent,
                sort_keys=sort_keys,
                ensure_ascii=ensure_ascii,
            )
    except (OSError, PermissionError) as exc:
        raise ConfigError(
            f"Failed to write config to {path}: {exc}"
        ) from exc

    return path


# ---------------------------------------------------------------------------
# Config to CLI args
# ---------------------------------------------------------------------------

def _flatten_for_cli(
    config: Dict[str, Any],
    prefix: str = "",
) -> List[str]:
    """Flatten a config dict into CLI argument pairs.

    Args:
        config: Config dict to flatten.
        prefix: Current key prefix for recursion.

    Returns:
        List of CLI argument strings.
    """
    args: List[str] = []

    for key, value in config.items():
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            nested = _flatten_for_cli(value, full_key)
            args.extend(nested)
        elif isinstance(value, bool):
            if value:
                args.append(f"--{full_key}")
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (str, int, float)):
                    args.append(f"--{full_key}")
                    args.append(str(item))
                else:
                    args.append(f"--{full_key}")
                    args.append(json.dumps(item))
        elif value is not None:
            if isinstance(value, str):
                args.append(f"--{full_key}")
                args.append(value)
            else:
                args.append(f"--{full_key}")
                args.append(str(value))

    return args


def config_to_cli_args(
    config: Dict[str, Any],
) -> List[str]:
    """Convert a configuration dictionary to a CLI argument list.

    Nested keys become dot-separated (``--target.domain example.com``).
    Booleans become flags (``True`` → ``--flag``). Lists and values
    are expanded.

    Args:
        config: The configuration dictionary.

    Returns:
        List of CLI argument strings suitable for ``subprocess.run``
        or similar.

    Example:
        >>> config_to_cli_args({"target": {"domain": "ex.com", "port": 443}})
        ['--target.domain', 'ex.com', '--target.port', '443']
    """
    return _flatten_for_cli(config)


# ---------------------------------------------------------------------------
# Config path resolution
# ---------------------------------------------------------------------------

def resolve_config_path(path: Union[str, Path]) -> Path:
    """Resolve a configuration path relative to standard locations.

    Resolution order (first match wins):
    1. If path is absolute or already exists, use as-is.
    2. If relative and exists relative to CWD, use that.
    3. If relative to project root (parent of ``utils/``), use that.
    4. If relative to user home directory, use that.
    5. If relative to ``config/`` subdirectory of project root, use that.
    6. Otherwise, return the (non-existent) cwd-relative path.

    Args:
        path: The path string or Path object to resolve.

    Returns:
        Resolved absolute Path.

    Example:
        >>> resolve_config_path("hercules.json")
        WindowsPath('C:/project/config/hercules.json')
    """
    path = Path(path)

    # Absolute or already exists
    if path.is_absolute():
        return path.resolve()

    if path.exists():
        return path.resolve()

    # Relative to CWD
    cwd_path = Path.cwd() / path
    if cwd_path.exists():
        return cwd_path.resolve()

    # Relative to project root
    project_path = PROJECT_ROOT / path
    if project_path.exists():
        return project_path.resolve()

    # Relative to config dir under project
    config_dir_path = PROJECT_ROOT / DEFAULT_CONFIG_DIR / path
    if config_dir_path.exists():
        return config_dir_path.resolve()

    # Relative to home directory
    home_path = HOME_DIR / path
    if home_path.exists():
        return home_path.resolve()

    # Fallback: return CWD-relative resolved path
    return cwd_path.resolve()


# ---------------------------------------------------------------------------
# Dict diff utility
# ---------------------------------------------------------------------------

def config_diff(
    old: Dict[str, Any],
    new: Dict[str, Any],
    *,
    prefix: str = "",
) -> Dict[str, Tuple[Any, Any]]:
    """Compute the differences between two configuration dicts.

    Args:
        old: Old config dict.
        new: New config dict.
        prefix: Internal recursion prefix.

    Returns:
        Dict mapping dot-separated key paths to ``(old_value, new_value)``
        tuples for values that differ.
    """
    diffs: Dict[str, Tuple[Any, Any]] = {}
    all_keys = set(old.keys()) | set(new.keys())

    for key in all_keys:
        full_key = f"{prefix}.{key}" if prefix else key
        old_val = old.get(key)
        new_val = new.get(key)

        if isinstance(old_val, dict) and isinstance(new_val, dict):
            nested = config_diff(old_val, new_val, prefix=full_key)
            diffs.update(nested)
        elif old_val != new_val:
            diffs[full_key] = (old_val, new_val)

    return diffs


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "load_json_config",
    "load_env_config",
    "merge_configs",
    "get_config_value",
    "set_config_value",
    "validate_config",
    "ConfigManager",
    "save_config",
    "config_to_cli_args",
    "resolve_config_path",
    "config_diff",
    "ConfigError",
    "ConfigValidationError",
    "ConfigNotFoundError",
]
