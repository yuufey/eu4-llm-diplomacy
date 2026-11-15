"""Offline contracts for the pinned CWTools scope-rule reader."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from bridge.information import cwtools_rules


ROOT = Path(__file__).resolve().parents[2]
VENDOR_DIR = ROOT / "third_party/cwtools-eu4-config"


class CwtoolsScopeRuleTests(unittest.TestCase):
    def workspace_copy(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        vendor_dir = root / "third_party/cwtools-eu4-config"
        vendor_dir.mkdir(parents=True)
        shutil.copyfile(VENDOR_DIR.with_name(VENDOR_DIR.name + ".vendor.json"), vendor_dir / "VENDOR.json")
        shutil.copyfile(VENDOR_DIR / "scopes.cwt", vendor_dir / "scopes.cwt")
        self.addCleanup(temp.cleanup)
        return root, vendor_dir

    def test_real_trade_node_aliases_and_parent_are_pinned_and_json_safe(self):
        rules = cwtools_rules.load_scope_rules()
        trade_node = cwtools_rules.trade_node_scope_rule()

        self.assertEqual(rules["aliases"]["trade_node"], "Trade Node")
        self.assertEqual(rules["aliases"]["tradenode"], "Trade Node")
        self.assertEqual(rules["is_subscope_of"]["Trade Node"], ["Province"])
        self.assertEqual(trade_node["name"], "Trade Node")
        self.assertEqual(trade_node["aliases"], ["trade_node", "tradenode"])
        self.assertEqual(trade_node["parents"], ["Province"])
        self.assertEqual(trade_node["source"]["commit"], "a85622d368bbb7afca938ed70fdd5eda44aec769")
        self.assertEqual(trade_node["source"]["license"], "MIT")
        self.assertEqual(trade_node["source"]["file_sha256"],
                         hashlib.sha256((VENDOR_DIR / "scopes.cwt").read_bytes()).hexdigest())
        json.dumps(rules, ensure_ascii=False, allow_nan=False)
        json.dumps(trade_node, ensure_ascii=False, allow_nan=False)

    def test_submodule_lf_and_crlf_checkouts_have_identical_rules(self):
        root, vendor_dir = self.workspace_copy()
        path = vendor_dir / "scopes.cwt"
        canonical = path.read_bytes().replace(b"\r\n", b"\n")
        path.write_bytes(canonical)
        lf = cwtools_rules.load_scope_rules(root)
        path.write_bytes(canonical.replace(b"\n", b"\r\n"))
        crlf = cwtools_rules.load_scope_rules(root)
        self.assertEqual(lf["scopes"], crlf["scopes"])
        self.assertEqual(lf["rule_source"]["canonical_lf_sha256"],
                         crlf["rule_source"]["canonical_lf_sha256"])

    def test_vendor_schema_or_commit_tampering_is_rejected(self):
        root, vendor_dir = self.workspace_copy()
        vendor_path = vendor_dir / "VENDOR.json"
        vendor = json.loads(vendor_path.read_text(encoding="utf-8"))
        vendor["commit"] = "0" * 40
        vendor_path.write_text(json.dumps(vendor), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "VENDOR.json schema, commit"):
            cwtools_rules.load_scope_rules(root)

    def test_malformed_vendor_manifest_is_rejected(self):
        root, vendor_dir = self.workspace_copy()
        (vendor_dir / "VENDOR.json").write_bytes(
            b'{"schema":"cwtools-eu4-config.vendored-scope-rules.v1",'
            b'"schema":"duplicate"}'
        )
        with self.assertRaisesRegex(ValueError, "Malformed CWTools vendor manifest"):
            cwtools_rules.load_scope_rules(root)

    def test_consumed_scope_tampering_and_oversize_are_rejected(self):
        root, vendor_dir = self.workspace_copy()
        scopes_path = vendor_dir / "scopes.cwt"
        raw = scopes_path.read_bytes()
        self.assertIn(b"tradenode", raw)
        scopes_path.write_bytes(raw.replace(b"tradenode", b"tradenoDe", 1))
        with self.assertRaisesRegex(ValueError, "scopes.cwt bytes or SHA-256 mismatch"):
            cwtools_rules.load_scope_rules(root)

        scopes_path.write_bytes(b"x" * (cwtools_rules._MAX_SCOPE_FILE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "exceeds byte limit"):
            cwtools_rules.load_scope_rules(root)

    def test_malformed_cwt_structure_is_rejected_even_with_matching_reviewed_pin(self):
        root, vendor_dir = self.workspace_copy()
        raw = b"scopes = { Trade Node = { aliases = { trade_node tradenode }"
        vendor = json.loads((vendor_dir / "VENDOR.json").read_text(encoding="utf-8"))
        digest = hashlib.sha256(raw).hexdigest()
        vendor["consumed_files"]["scopes.cwt"] = {"bytes": len(raw), "sha256": digest}
        (vendor_dir / "scopes.cwt").write_bytes(raw)
        (vendor_dir / "VENDOR.json").write_text(json.dumps(vendor), encoding="utf-8")
        with patch.object(cwtools_rules, "_SCOPES_BYTES", len(raw)), \
                patch.object(cwtools_rules, "_SCOPES_SHA256", digest), \
                patch.object(cwtools_rules, "_SCOPES_LF_BYTES", len(raw)), \
                patch.object(cwtools_rules, "_SCOPES_LF_SHA256", digest), \
                patch.object(cwtools_rules, "_EXPECTED_VENDOR", vendor):
            with self.assertRaisesRegex(ValueError, "Malformed scopes.cwt text"):
                cwtools_rules.load_scope_rules(root)


if __name__ == "__main__":
    unittest.main()
