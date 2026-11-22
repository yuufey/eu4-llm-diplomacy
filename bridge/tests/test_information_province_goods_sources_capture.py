"""Offline tests for the province-goods capture boundary wrappers.

These tests fake the leaf result, callback table, reader and shared observer
boundary. They do not load a profile, contact a process, or exercise the leaf's
memory decoding.
"""
import unittest
from unittest.mock import patch

from bridge.information import province_goods_sources_capture as capture
from bridge.information import province_goods_sources_memory as leaf


class DescriptorQualificationTests(unittest.TestCase):
    BASE = 0x10000000
    MANAGER = 0x40000000
    RECORD = 0x30000000
    NAME_POINTER = 0x50000000
    FIELD = leaf.FIELD_GOODS_SOURCE

    def binding(self):
        return {"record_pointer": hex(self.RECORD), "province_id": 183}

    def descriptor(self, key="trade_goods_size_modifier", processor=0):
        encoded = key.encode("ascii")
        raw = bytearray(0x60)
        raw[0:8] = self.NAME_POINTER.to_bytes(8, "little")
        raw[0x10:0x18] = len(encoded).to_bytes(8, "little")
        raw[0x18:0x20] = max(32, len(encoded)).to_bytes(8, "little")
        raw[0x40:0x48] = processor.to_bytes(8, "little")
        return bytes(raw), encoded + b"\0"

    def known_field(self):
        return {
            "status": "known",
            "value": {"cached_component_raw": 1200},
            "raw_inputs": {"leaf_capture": "fake"},
        }

    def run_qualification(self, *, key="trade_goods_size_modifier", processor=0,
                          change_descriptor_on_recheck=False):
        descriptor_address = self.MANAGER + 21 * 0x60
        cell_address = self.BASE + 0x2358060
        descriptor_raw, name_raw = self.descriptor(key, processor)
        changed = bytearray(descriptor_raw)
        changed[0x40] ^= 1

        class Reader:
            def __init__(self):
                self.calls = []

            def read(inner, address, size, label):
                inner.calls.append((address, size, label))
                if address == cell_address and size == 8:
                    return self.MANAGER.to_bytes(8, "little")
                if address == descriptor_address and size == 0x60:
                    if change_descriptor_on_recheck and ".descriptor_stability." in label:
                        return bytes(changed)
                    return descriptor_raw
                if address == self.NAME_POINTER and size == len(name_raw):
                    return name_raw
                raise AssertionError((hex(address), size, label))

        reader = Reader()
        field = self.known_field()
        leaf_result = {self.FIELD: field}
        with patch.object(leaf, "read_fields", return_value=leaf_result) as read_fields:
            result = capture._qualified_fields(reader, self.BASE, self.binding(), (self.FIELD,))
        read_fields.assert_called_once_with(reader, self.BASE, self.binding(), (self.FIELD,))
        return result, field, reader, descriptor_address, leaf_result

    def test_unknown_leaf_result_does_not_read_a_descriptor(self):
        unknown = {self.FIELD: {"status": "unknown", "reason": "leaf_unknown"}}
        reader = type("Reader", (), {"read": lambda *args: self.fail("reader must stay unused")})()
        with patch.object(leaf, "read_fields", return_value=unknown), \
             patch.object(capture._quality, "_TraceReader") as trace_reader:
            result = capture._qualified_fields(reader, self.BASE, self.binding(), (self.FIELD,))
        self.assertIs(result, unknown)
        trace_reader.assert_not_called()

    def test_known_leaf_qualifies_only_descriptor_21_with_exact_key_and_null_processor(self):
        result, field, reader, address, _ = self.run_qualification()
        self.assertIs(result[self.FIELD], field)
        self.assertEqual(field["status"], "known")
        self.assertTrue(field["value"]["descriptor_qualified"])
        qualification = field["raw_inputs"]["descriptor_qualification"]
        self.assertEqual(qualification["key"]["key"], "trade_goods_size_modifier")
        self.assertEqual(qualification["descriptor_address"], hex(address))
        self.assertIs(qualification["processor_null"], True)
        descriptor_reads = [row for row in reader.calls if row[1] == 0x60]
        self.assertEqual([row[0] for row in descriptor_reads], [address, address])
        self.assertEqual(descriptor_reads[0][2], "province_goods_sources.descriptor21")
        self.assertIn("descriptor_stability.1", descriptor_reads[1][2])
        self.assertFalse(any(row[0] in (self.MANAGER + 20 * 0x60,
                                        self.MANAGER + 22 * 0x60)
                             for row in reader.calls))

    def test_non_null_processor_wrong_key_and_recheck_drift_are_unknown(self):
        cases = (
            {"processor": 0x1234},
            {"key": "another_modifier"},
            {"change_descriptor_on_recheck": True},
        )
        for options in cases:
            with self.subTest(options=options):
                result, _, _, _, _ = self.run_qualification(**options)
                field = result[self.FIELD]
                self.assertEqual(field["status"], "unknown")
                self.assertEqual(field["reason"],
                                 "PROVINCE_GOODS_SOURCE_DESCRIPTOR_UNVERIFIED")


class CallbackTableBoundaryTests(unittest.TestCase):
    BASE = 0x10000000
    PROVINCE_ID = 183

    def fixture(self, *, changed=False, mismatch=False):
        target_rvas = [hex(0x1000 + index * 0x10) for index in range(36)]
        expected = b"".join(
            (self.BASE + int(rva, 0)).to_bytes(8, "little")
            for rva in target_rvas
        )
        after = bytearray(expected)
        if changed:
            after[-1] ^= 1
        before = bytes(0x120) if mismatch else expected
        start = self.BASE + 0x200

        class Reader:
            def __init__(inner):
                inner.calls = []

            def read(inner, address, size, label):
                inner.calls.append((address, size, label))
                if address != start or size != 288:
                    raise AssertionError((hex(address), size, label))
                return before if label.endswith("before") else bytes(after)

        profile = {"layout": {"province_goods_sources": {
            "callback_table": {"rva": "0x200", "target_rvas": target_rvas}
        }}}
        return profile, Reader(), start, expected

    @staticmethod
    def dispatch_backend(reader, module_base, country, profile, *, backend_reader=None):
        if backend_reader is None:
            raise AssertionError("capture did not supply its guarded backend reader")
        return backend_reader(reader, module_base, country)

    def test_profile_callback_table_value_mismatch_blocks_leaf_read(self):
        profile, reader, start, _ = self.fixture(mismatch=True)
        with patch.object(capture._owner, "_observe", side_effect=self.dispatch_backend), \
             patch.object(capture._province, "read_two_pass") as read_two_pass:
            with self.assertRaisesRegex(ValueError, "PROVINCE_GOODS_SOURCE_CALLBACK_MISMATCH"):
                capture._observe_for(self.PROVINCE_ID)(reader, self.BASE, "FRA", profile)
        read_two_pass.assert_not_called()
        self.assertEqual(reader.calls, [(start, 288, "province_goods_sources.callbacks.before")])

    def test_callback_table_change_after_backend_observation_is_rejected(self):
        profile, reader, start, _ = self.fixture(changed=True)
        with patch.object(capture._owner, "_observe", side_effect=self.dispatch_backend), \
             patch.object(capture._province, "read_two_pass", return_value={"status": "observed"}) as read_two_pass:
            with self.assertRaisesRegex(ValueError, "PROVINCE_GOODS_SOURCE_CALLBACK_CHANGED"):
                capture._observe_for(self.PROVINCE_ID)(reader, self.BASE, "FRA", profile)
        read_two_pass.assert_called_once()
        self.assertEqual([row[0:2] for row in reader.calls], [(start, 288), (start, 288)])

    def test_stable_callback_table_wraps_the_two_pass_observation(self):
        profile, reader, start, expected = self.fixture()
        backend_result = {"status": "observed", "targets": []}
        with patch.object(capture._owner, "_observe", side_effect=self.dispatch_backend), \
             patch.object(capture._province, "read_two_pass", return_value=backend_result) as read_two_pass:
            result = capture._observe_for(self.PROVINCE_ID)(reader, self.BASE, "FRA", profile)
        self.assertIs(result, backend_result)
        self.assertEqual(result["callback_table"], {
            "address": hex(start), "raw_hex": expected.hex(),
            "target_rvas": profile["layout"]["province_goods_sources"]["callback_table"]["target_rvas"],
            "stable": True,
        })
        read_two_pass.assert_called_once()
        self.assertEqual(read_two_pass.call_args.kwargs["observer"], "FRA")
        self.assertEqual(read_two_pass.call_args.kwargs["fields"], (leaf.FIELD_GOODS_SOURCE,))
        self.assertIs(read_two_pass.call_args.kwargs["read_fields"], capture._qualified_fields)
        self.assertEqual([row[0:2] for row in reader.calls], [(start, 288), (start, 288)])


class CaptureEnvelopeTests(unittest.TestCase):
    def valid_report(self):
        return {
            "schema": capture.SCHEMA,
            "observer": "FRA",
            "object": {"type": "province", "province_id": 183},
            "capture": {"status": "observed"},
        }

    def test_bad_schema_object_and_boolean_request_id_are_rejected_before_common_validation(self):
        wrong_schema = self.valid_report()
        wrong_schema["schema"] = "wrong.schema"
        wrong_object = self.valid_report()
        wrong_object["object"] = {"type": "country", "province_id": 183}
        wrong_object_id = self.valid_report()
        wrong_object_id["object"]["province_id"] = 184
        cases = (
            (wrong_schema, 183),
            (wrong_object, 183),
            (wrong_object_id, 183),
            (self.valid_report(), True),
        )
        with patch.object(capture._owner, "_validate_capture_common", return_value=True) as common:
            for report, province_id in cases:
                with self.subTest(schema=report["schema"], province_id=province_id,
                                  object=report["object"]):
                    self.assertFalse(capture.validate_capture(report, {"observer": "FRA"}, 123, province_id))
        common.assert_not_called()

    def test_valid_capture_envelope_delegates_to_common_raw_replay(self):
        report = self.valid_report()
        context = {"session_id": "fake-session", "observer": "FRA"}
        observe = lambda *args, **kwargs: {"stable": True}
        with patch.object(capture, "_observe_for", return_value=observe) as observe_for, \
             patch.object(capture._owner, "_validate_capture_common", return_value=True) as common:
            self.assertTrue(capture.validate_capture(report, context, 123, 183))
        observe_for.assert_called_once_with(183, "FRA")
        common.assert_called_once()
        args, kwargs = common.call_args
        self.assertEqual(args[:4], (report["capture"], context, 123, "FRA"))
        self.assertEqual(kwargs["schema"], capture.INNER_SCHEMA)
        self.assertIs(kwargs["observe"], observe)
        self.assertIs(kwargs["allow_observer_target"], True)
        self.assertIs(kwargs["observer_scoped"], True)
        self.assertIs(kwargs["require_access"], True)


if __name__ == "__main__":
    unittest.main()
