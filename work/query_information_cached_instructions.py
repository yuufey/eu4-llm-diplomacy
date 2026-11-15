"""Read one cached function's instructions without invoking its decompiler.

Preserve the complete provider record.  Result shape is checked conservatively;
the caller must inspect the actual instruction fields before interpreting them.
"""
from argparse import Namespace
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reverse_engineering import cache_query as cq


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", args.address):
        parser.error("--run and one explicit function address are required")
    output = args.output.resolve()
    output.relative_to(ROOT / "work/runtime")
    original_popen = cq.psutil.Popen

    def launch(command, **kwargs):
        assert command[-7] == "function"
        command = list(command)
        command[-7] = "instructions"
        with (output / "operation-adaptation.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump({
                "operation": "read_function_instructions", "analysis_address": args.address,
                "command": command, "supervisor_source": "reverse_engineering/cache_query.py",
                "decompiler_requested": False,
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            }, stream, indent=2)
            stream.write("\n")
        return original_popen(command, **kwargs)

    def validate(evidence, request, digest, manifest_sha, database_sha, metadata):
        profile = evidence.get("analysis_profile", {}).get("parameters", {})
        result = evidence.get("raw_result")
        # Collection is not semantic acceptance of any inferred field or layout.
        shape = isinstance(result, (list, dict)) and bool(result)
        if shape:
            shape = len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= 16 * 1024 * 1024
        return bool(shape
            and evidence.get("operation") == "read_function_instructions"
            and evidence.get("subject", {}).get("digest", {}).get("sha256") == digest
            and evidence.get("provider", {}).get("version") == metadata["ghidra_version"]
            and profile.get("analyzer_preset") == cq.PRESET
            and profile.get("local_adapter_sha256") == request["adapter_sha256"]
            and profile.get("completed_manifest_sha256") == manifest_sha
            and profile.get("completed_database_sha256") == database_sha)

    query = Namespace(node=args.address, binary=None,
        cache=ROOT / "work/runtime/ghidra-full/b23fa0e1f698d31b-20261014T054913Z-6dda97",
        config=Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "config.toml",
        timeout=180, output=output)
    with patch.object(cq.psutil, "Popen", launch), patch.object(cq, "_validate_cached_result", validate):
        return cq.query(query)


if __name__ == "__main__":
    raise SystemExit(main())
