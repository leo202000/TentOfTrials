"""Focused validation tests for tools/config_generator.py helpers.

Covers generate_config(), merge_config(), mask_sensitive(), and
verifies SENSITIVE_KEYS is free of duplicates while preserving
the same redaction behavior.
"""
import os
import sys
import unittest
import copy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import config_generator as cg


class TestSensitiveKeys(unittest.TestCase):
    def test_no_duplicates(self):
        self.assertEqual(len(cg.SENSITIVE_KEYS), len(set(cg.SENSITIVE_KEYS)))

    def test_expected_keys_present(self):
        for key in ("database.password", "redis.password", "auth.jwt_secret"):
            self.assertIn(key, cg.SENSITIVE_KEYS)


class TestGenerateConfig(unittest.TestCase):
    def test_development_overrides(self):
        cfg = cg.generate_config("development")
        self.assertEqual(cfg["app"]["environment"], "development")
        self.assertTrue(cfg["app"]["debug"])
        self.assertEqual(cfg["app"]["log_level"], "debug")
        self.assertEqual(cfg["database"]["name"], "tent_dev")
        self.assertEqual(cfg["market"]["rate_limit_per_second"], 1000)
        self.assertEqual(cfg["auth"]["jwt_expiry_minutes"], 1440)

    def test_production_overrides(self):
        cfg = cg.generate_config("production")
        self.assertEqual(cfg["app"]["environment"], "production")
        self.assertFalse(cfg["app"]["debug"])
        self.assertEqual(cfg["app"]["log_level"], "info")
        self.assertEqual(cfg["database"]["name"], "tent_production")
        self.assertEqual(cfg["database"]["pool_max"], 50)
        self.assertEqual(cfg["database"]["pool_min"], 10)
        self.assertEqual(cfg["market"]["rate_limit_per_second"], 10)
        self.assertEqual(cfg["market"]["rate_limit_burst"], 20)
        self.assertEqual(cfg["auth"]["jwt_expiry_minutes"], 60)
        self.assertTrue(cfg["auth"]["mfa_required"])
        self.assertEqual(cfg["monitoring"]["tracing_sample_rate"], 0.01)
        self.assertFalse(cfg["monitoring"]["profiling_enabled"])

    def test_staging_overrides(self):
        cfg = cg.generate_config("staging")
        self.assertEqual(cfg["app"]["environment"], "staging")
        self.assertEqual(cfg["database"]["name"], "tent_staging")
        self.assertEqual(cfg["database"]["pool_max"], 20)
        self.assertEqual(cfg["monitoring"]["tracing_sample_rate"], 0.5)

    def test_unknown_env_uses_defaults(self):
        cfg = cg.generate_config("nonexistent")
        self.assertEqual(cfg["app"]["environment"], "development")
        self.assertEqual(cfg["database"]["name"], "tent_dev")

    def test_custom_overrides_applied(self):
        overrides = {"server": {"port": 9999}, "database": {"host": "db.example.com"}}
        cfg = cg.generate_config("development", overrides)
        self.assertEqual(cfg["server"]["port"], 9999)
        self.assertEqual(cfg["database"]["host"], "db.example.com")
        self.assertEqual(cfg["database"]["name"], "tent_dev")

    def test_default_config_has_sensitive_placeholders(self):
        cfg = cg.generate_config("development")
        self.assertEqual(cfg["database"]["password"], "")
        self.assertEqual(cfg["redis"]["password"], "")
        self.assertEqual(cfg["auth"]["jwt_secret"], "")


class TestMergeConfig(unittest.TestCase):
    def test_shallow_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = cg.merge_config(base, override)
        self.assertEqual(result, {"a": 1, "b": 3, "c": 4})

    def test_recursive_merge(self):
        base = {"db": {"host": "localhost", "port": 5432}, "app": "x"}
        override = {"db": {"port": 9999}}
        result = cg.merge_config(base, override)
        self.assertEqual(result["db"]["host"], "localhost")
        self.assertEqual(result["db"]["port"], 9999)
        self.assertEqual(result["app"], "x")

    def test_does_not_mutate_base(self):
        base = {"db": {"host": "localhost", "port": 5432}}
        base_copy = copy.deepcopy(base)
        cg.merge_config(base, {"db": {"port": 9999}})
        self.assertEqual(base, base_copy)

    def test_does_not_mutate_override(self):
        override = {"db": {"port": 9999}}
        override_copy = copy.deepcopy(override)
        cg.merge_config({"db": {"host": "h"}}, override)
        self.assertEqual(override, override_copy)

    def test_override_replaces_non_dict_with_dict(self):
        base = {"key": "string"}
        override = {"key": {"nested": True}}
        result = cg.merge_config(base, override)
        self.assertEqual(result["key"], {"nested": True})

    def test_nested_three_levels(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"c": 99}}}
        result = cg.merge_config(base, override)
        self.assertEqual(result["a"]["b"]["c"], 99)
        self.assertEqual(result["a"]["b"]["d"], 2)

    def test_empty_override(self):
        base = {"a": 1}
        result = cg.merge_config(base, {})
        self.assertEqual(result, {"a": 1})


class TestMaskSensitive(unittest.TestCase):
    def _masked_config(self):
        return {
            "database": {"host": "localhost", "password": "super-secret"},
            "redis": {"port": 6379, "password": "redis-pw"},
            "auth": {"jwt_secret": "jwt-token-value", "jwt_expiry_minutes": 60},
            "app": {"name": "tent-of-trials"},
        }

    def test_database_password_redacted(self):
        masked = cg.mask_sensitive(self._masked_config())
        self.assertEqual(masked["database"]["password"], "***REDACTED***")

    def test_redis_password_redacted(self):
        masked = cg.mask_sensitive(self._masked_config())
        self.assertEqual(masked["redis"]["password"], "***REDACTED***")

    def test_jwt_secret_redacted(self):
        masked = cg.mask_sensitive(self._masked_config())
        self.assertEqual(masked["auth"]["jwt_secret"], "***REDACTED***")

    def test_non_sensitive_values_preserved(self):
        masked = cg.mask_sensitive(self._masked_config())
        self.assertEqual(masked["database"]["host"], "localhost")
        self.assertEqual(masked["redis"]["port"], 6379)
        self.assertEqual(masked["auth"]["jwt_expiry_minutes"], 60)
        self.assertEqual(masked["app"]["name"], "tent-of-trials")

    def test_does_not_mutate_input(self):
        cfg = self._masked_config()
        import copy as _copy
        snapshot = _copy.deepcopy(cfg)
        cg.mask_sensitive(cfg)
        self.assertEqual(cfg, snapshot)

    def test_empty_password_still_redacted(self):
        cfg = {"database": {"password": ""}}
        masked = cg.mask_sensitive(cfg)
        self.assertEqual(masked["database"]["password"], "***REDACTED***")

    def test_nested_prefix_tracking(self):
        cfg = {"auth": {"jwt_secret": "s", "sub": {"jwt_secret": "deep"}}}
        masked = cg.mask_sensitive(cfg)
        self.assertEqual(masked["auth"]["jwt_secret"], "***REDACTED***")
        self.assertEqual(masked["auth"]["sub"], {"jwt_secret": "deep"})

    def test_generate_then_mask_integration(self):
        cfg = cg.generate_config("production", {"database": {"password": "p"}, "auth": {"jwt_secret": "j"}})
        masked = cg.mask_sensitive(cfg)
        self.assertEqual(masked["database"]["password"], "***REDACTED***")
        self.assertEqual(masked["auth"]["jwt_secret"], "***REDACTED***")
        self.assertEqual(masked["app"]["environment"], "production")


class TestRedactionBehaviorUnchanged(unittest.TestCase):
    """Verify deduplication did not change which keys get redacted."""

    def test_all_original_sensitive_keys_still_redact(self):
        original_keys = ["database.password", "redis.password", "auth.jwt_secret"]
        for key in original_keys:
            parts = key.split(".")
            cfg = {parts[0]: {parts[1]: "secret-value"}}
            masked = cg.mask_sensitive(cfg)
            self.assertEqual(
                masked[parts[0]][parts[1]],
                "***REDACTED***",
                "Key %s should still be redacted" % key,
            )


if __name__ == "__main__":
    unittest.main()
