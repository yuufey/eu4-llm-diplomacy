"""Bounded reads and strict pin validation for the mission prerequisite profile."""
from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bridge.information import mission_prerequisite_profile as pp


class FakeStream:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.read_sizes: list[int] = []

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.payload[:size]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeProfilePath:
    def __init__(self, stat_size: int, payload: bytes):
        self.stat_size = stat_size
        self.stream = FakeStream(payload)
        self.events: list[str] = []

    def stat(self):
        self.events.append('stat')
        return SimpleNamespace(st_size=self.stat_size)

    def open(self, mode: str):
        self.events.append('open')
        if mode != 'rb':
            raise AssertionError(f'unexpected mode: {mode}')
        return self.stream


class MissionPrerequisiteProfileBoundsTests(unittest.TestCase):
    def test_empty_and_oversized_files_are_rejected_before_open(self):
        for size in (0, pp.MAX_PROFILE_BYTES + 1):
            with self.subTest(size=size):
                path = FakeProfilePath(size, b'')
                with patch.object(pp, 'PROFILE_FILE', path):
                    with self.assertRaisesRegex(ValueError, 'PREREQUISITE_PROFILE_PIN_MISMATCH'):
                        pp.load_profile()
                self.assertEqual(path.events, ['stat'])
                self.assertEqual(path.stream.read_sizes, [])

    def test_growth_shrinkage_and_same_length_corruption_fail_closed(self):
        pinned = pp.PROFILE_FILE.read_bytes()
        damaged = bytearray(pinned)
        damaged[-1] ^= 1
        cases = {
            'growth_after_stat': pinned + b' ',
            'shrink_after_stat': pinned[:-1],
            'same_length_corruption': bytes(damaged),
            'growth_beyond_read_cap': pinned + bytes(pp.MAX_PROFILE_BYTES + 1),
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                path = FakeProfilePath(len(pinned), payload)
                with patch.object(pp, 'PROFILE_FILE', path):
                    with self.assertRaisesRegex(ValueError, 'PREREQUISITE_PROFILE_PIN_MISMATCH'):
                        pp.load_profile()
                self.assertEqual(path.events, ['stat', 'open'])
                self.assertEqual(path.stream.read_sizes, [pp.MAX_PROFILE_BYTES + 1])

    def test_current_pinned_profile_loads(self):
        profile = pp.load_profile()
        self.assertEqual(profile['schema'], 'eu4.mission_prerequisite_memory.v1')
        self.assertEqual(profile['executable_sha256'], pp.EXE_SHA256)


if __name__ == '__main__':
    unittest.main()
