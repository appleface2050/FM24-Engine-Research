"""验证审核复现入口确实拒绝错误输入和断裂引用；不验证FM24比赛语义。"""

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_goal_lifecycle as verifier


class TargetIdentityTests(unittest.TestCase):
    """使用可手工核对的微型PE头，不需要游戏文件。"""

    def setUp(self):
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHI", data, 0x84, 0x8664, 1, 7)
        struct.pack_into("<H", data, 0x98, 0x20B)
        struct.pack_into("<I", data, 0x98 + 16, 0x1000)
        struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
        struct.pack_into("<I", data, 0x98 + 56, 0x2000)
        self.data = bytes(data)
        self.expected = {
            "file_size": 512,
            "sha256": hashlib.sha256(data).hexdigest(),
            "pe": {"machine": "0x8664", "time_date_stamp": "0x7", "section_count": 1,
                   "optional_magic": "0x20b", "image_base": "0x140000000",
                   "entry_point_rva": "0x1000", "size_of_image": 0x2000},
        }

    def test_same_input(self):
        verifier.verify_target_identity(self.data, self.expected)

    def test_same_size_different_content(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verifier.verify_target_identity(self.data[:-1] + b"\x01", self.expected)

    def test_different_size(self):
        with self.assertRaisesRegex(ValueError, "file size"):
            verifier.verify_target_identity(self.data[:-1], self.expected)

    def test_inconsistent_recorded_pe(self):
        self.expected["pe"]["entry_point_rva"] = "0x2000"
        with self.assertRaisesRegex(ValueError, "PE identity"):
            verifier.verify_target_identity(self.data, self.expected)


class EvidenceIndexTests(unittest.TestCase):
    """微型索引只构造当前入口实际检查的引用和连接。"""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        root_patch = patch.object(verifier, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        for name in ("README.md", "RESEARCH_MAP.md", "OPEN_QUESTIONS.md",
                     "20261017_有效进球与比分状态生命周期.md"):
            (self.root / name).write_text("[证据](evidence.json)\n")
        (self.root / "identity.json").write_text("{}\n")
        (self.root / "evidence.json").write_text(json.dumps({"native_assertions": [{"va": "0x1000"}]}))
        self.index = {"target_identity": "identity.json", "mechanisms": [{
            "id": "example", "upstream": [], "downstream": [],
            "evidence": {"raw": ["evidence.json"]},
            "connections": [{"callsite": "0x1000", "evidence": "evidence.json"}],
        }]}

    def save(self):
        """写出当前用例的索引。"""
        (self.root / "EVIDENCE_INDEX.json").write_text(json.dumps(self.index))

    def test_valid_index(self):
        self.save()
        verifier.verify_index()

    def test_unknown_mechanism(self):
        self.index["mechanisms"][0]["upstream"] = ["missing"]
        self.save()
        with self.assertRaisesRegex(ValueError, "Unknown mechanism"):
            verifier.verify_index()

    def test_missing_local_link(self):
        self.save()
        (self.root / "README.md").write_text("[断裂链接](missing.md)\n")
        with self.assertRaisesRegex(ValueError, "Missing local document link"):
            verifier.verify_index()

    def test_callsite_without_byte_assertion(self):
        self.index["mechanisms"][0]["connections"][0]["callsite"] = "0x2000"
        self.save()
        with self.assertRaisesRegex(ValueError, "no byte assertion"):
            verifier.verify_index()


if __name__ == "__main__":
    unittest.main()
