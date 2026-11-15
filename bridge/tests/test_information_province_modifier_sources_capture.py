"""Fake-boundary tests for the province modifier-source capture envelope."""
import unittest
from unittest.mock import patch

from bridge.information import province_modifier_sources_capture as capture


class CaptureEnvelopeTests(unittest.TestCase):
    PROVINCE_ID = 187

    def valid_report(self):
        return {
            "schema": capture.SCHEMA,
            "observer": "FRA",
            "object": {"type": "province", "province_id": self.PROVINCE_ID},
            "capture": {"status": "observed"},
        }

    def test_bad_envelope_schema_object_and_boolean_province_ids_skip_common_validation(self):
        wrong_schema = self.valid_report()
        wrong_schema["schema"] = "information.wrong.v2"
        wrong_object_type = self.valid_report()
        wrong_object_type["object"]["type"] = "country"
        wrong_object_id = self.valid_report()
        wrong_object_id["object"]["province_id"] = self.PROVINCE_ID + 1
        cases = (
            (wrong_schema, self.PROVINCE_ID),
            (wrong_object_type, self.PROVINCE_ID),
            (wrong_object_id, self.PROVINCE_ID),
            (self.valid_report(), True),
        )
        with patch.object(capture._owner, "_validate_capture_common", return_value=True) as common:
            for report, province_id in cases:
                with self.subTest(schema=report["schema"], province_id=province_id,
                                  object=report["object"]):
                    self.assertFalse(capture.validate_capture(report, {}, 123, province_id))
        common.assert_not_called()

    def test_valid_envelope_delegates_to_the_shared_raw_replay_validator(self):
        report = self.valid_report()
        context = {"session_id": "fake-session"}
        observe = lambda *args, **kwargs: {"callback_table": {"stable": True}}
        with patch.object(capture, "_observe_for", return_value=observe) as observe_for, \
             patch.object(capture._owner, "_validate_capture_common", return_value=True) as common:
            self.assertTrue(capture.validate_capture(report, context, 123, self.PROVINCE_ID))

        observe_for.assert_called_once_with(self.PROVINCE_ID)
        common.assert_called_once()
        args, kwargs = common.call_args
        self.assertEqual(args[:4], (report["capture"], context, 123, "FRA"))
        self.assertEqual(kwargs["schema"], capture.INNER_SCHEMA)
        self.assertIs(kwargs["observe"], observe)
        self.assertIs(kwargs["allow_observer_target"], True)
        self.assertIs(kwargs["require_access"], True)


class CallbackTableBoundaryTests(unittest.TestCase):
    BASE = 0x10000000
    PROVINCE_ID = 187

    def fixture(self, *, bad_pointer=False, drift_after=False):
        target_rvas = [hex(0x1000 + index * 0x10) for index in range(36)]
        expected = b"".join(
            (self.BASE + int(rva, 0)).to_bytes(8, "little")
            for rva in target_rvas
        )
        before = bytearray(expected)
        after = bytearray(expected)
        if bad_pointer:
            before[7 * 8:8 * 8] = bytes(8)
        if drift_after:
            after[-1] ^= 1
        start = self.BASE + 0x200

        class Reader:
            def __init__(inner):
                inner.calls = []

            def read(inner, address, size, label):
                inner.calls.append((address, size, label))
                if address != start or size != 288:
                    raise AssertionError((hex(address), size, label))
                return bytes(after if label.endswith("after") else before)

        profile = {"layout": {"province_goods_sources": {
            "callback_table": {"rva": "0x200", "target_rvas": target_rvas}
        }}}
        return profile, Reader(), start, expected

    @staticmethod
    def dispatch_backend(reader, module_base, country, profile, *, backend_reader=None):
        if backend_reader is None:
            raise AssertionError("capture did not supply its guarded backend reader")
        return backend_reader(reader, module_base, country)

    def test_bad_callback_target_pointer_is_rejected_before_leaf_observation(self):
        profile, reader, start, _ = self.fixture(bad_pointer=True)
        with patch.object(capture._owner, "_observe", side_effect=self.dispatch_backend), \
             patch.object(capture._province, "read_two_pass") as read_two_pass:
            with self.assertRaisesRegex(ValueError, "PROVINCE_SOURCE_CALLBACK_MISMATCH"):
                capture._observe_for(self.PROVINCE_ID)(reader, self.BASE, "FRA", profile)

        read_two_pass.assert_not_called()
        self.assertEqual(reader.calls, [
            (start, 288, "province_sources.callbacks.before"),
        ])

    def test_callback_table_drift_after_the_leaf_observation_is_rejected(self):
        profile, reader, start, _ = self.fixture(drift_after=True)
        with patch.object(capture._owner, "_observe", side_effect=self.dispatch_backend), \
             patch.object(capture._province, "read_two_pass", return_value={"status": "observed"}) as read_two_pass:
            with self.assertRaisesRegex(ValueError, "PROVINCE_SOURCE_CALLBACK_CHANGED"):
                capture._observe_for(self.PROVINCE_ID)(reader, self.BASE, "FRA", profile)

        read_two_pass.assert_called_once()
        self.assertEqual(reader.calls, [
            (start, 288, "province_sources.callbacks.before"),
            (start, 288, "province_sources.callbacks.after"),
        ])

    def test_stable_table_uses_one_shared_two_pass_reader_with_exact_leaf_function(self):
        profile, reader, start, expected = self.fixture()
        backend_result = {"status": "observed", "targets": []}
        leaf_read_fields = capture._leaf.read_fields
        with patch.object(capture._owner, "_observe", side_effect=self.dispatch_backend), \
             patch.object(capture._province, "read_two_pass", return_value=backend_result) as read_two_pass:
            result = capture._observe_for(self.PROVINCE_ID)(reader, self.BASE, "FRA", profile)

        self.assertIs(result, backend_result)
        self.assertEqual(result["callback_table"], {
            "address": hex(start), "raw_hex": expected.hex(),
            "target_rvas": profile["layout"]["province_goods_sources"]["callback_table"]["target_rvas"],
            "stable": True,
        })
        read_two_pass.assert_called_once_with(
            reader, self.BASE, self.PROVINCE_ID, observer="FRA",
            fields=(capture._leaf.FIELD,), read_fields=leaf_read_fields,
        )
        self.assertIs(read_two_pass.call_args.kwargs["read_fields"], leaf_read_fields)
        self.assertEqual(reader.calls, [
            (start, 288, "province_sources.callbacks.before"),
            (start, 288, "province_sources.callbacks.after"),
        ])


if __name__ == "__main__":
    unittest.main()
