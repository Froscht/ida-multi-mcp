"""Tests for instance_id.py — ID generation and collision resolution."""

from ida_multi_mcp.instance_id import (
    BASE36_CHARS,
    DEFAULT_ID_LENGTH,
    generate_instance_id,
    resolve_collision,
)
import pytest


class TestGenerateInstanceId:
    def test_deterministic_output(self):
        """Same inputs always produce the same ID."""
        id1 = generate_instance_id(123, 4567, "/tmp/test.i64")
        id2 = generate_instance_id(123, 4567, "/tmp/test.i64")
        assert id1 == id2

    def test_correct_length(self):
        """Default output is 4 characters."""
        result = generate_instance_id(1, 2, "x")
        assert len(result) == DEFAULT_ID_LENGTH

    def test_base36_charset(self):
        """All characters are valid base36."""
        result = generate_instance_id(999, 8080, "/some/path.i64")
        for ch in result:
            assert ch in BASE36_CHARS

    def test_different_inputs_produce_different_ids(self):
        """Different pid/port/path combos yield different IDs."""
        id_a = generate_instance_id(1, 100, "/a.i64")
        id_b = generate_instance_id(2, 200, "/b.i64")
        assert id_a != id_b

    def test_custom_length(self):
        """Explicit length parameter changes output size."""
        result = generate_instance_id(1, 2, "x", length=7)
        assert len(result) == 7


class TestResolveCollision:
    def test_no_collision_passthrough(self):
        """When no collision, returns the original candidate."""
        candidate = generate_instance_id(1, 2, "x")
        result = resolve_collision(candidate, set(), 1, 2, "x")
        assert result == candidate

    def test_collision_expands_to_five_chars(self):
        """On collision, expands to 5-char ID."""
        candidate = generate_instance_id(1, 2, "x")
        result = resolve_collision(candidate, {candidate}, 1, 2, "x")
        assert result != candidate
        assert len(result) == DEFAULT_ID_LENGTH + 1

    def test_suffix_fallback(self):
        """When both 4-char and 5-char collide, falls back to suffix."""
        candidate = generate_instance_id(1, 2, "x")
        expanded = generate_instance_id(1, 2, "x", length=5)
        existing = {candidate, expanded}
        result = resolve_collision(candidate, existing, 1, 2, "x")
        assert result not in existing
        assert len(result) == DEFAULT_ID_LENGTH + 1  # candidate + 1 suffix char

    def test_runtime_error_when_exhausted(self):
        """RuntimeError when all suffix combinations are taken."""
        candidate = generate_instance_id(1, 2, "x")
        expanded = generate_instance_id(1, 2, "x", length=5)
        # Block all 36 suffixes
        all_suffixed = {candidate + ch for ch in BASE36_CHARS}
        existing = {candidate, expanded} | all_suffixed
        with pytest.raises(RuntimeError, match="Cannot generate unique"):
            resolve_collision(candidate, existing, 1, 2, "x")
