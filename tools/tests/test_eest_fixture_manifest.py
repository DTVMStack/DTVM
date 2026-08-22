import json
import pathlib
import sys
import tempfile
import unittest

TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from eest_fixture_manifest import build_manifest


class EESTFixtureManifestTest(unittest.TestCase):
    def write_fixture(self, root: pathlib.Path, content: dict) -> None:
        fixture = root / "suite" / "sample.json"
        fixture.parent.mkdir(parents=True)
        fixture.write_text(json.dumps(content), encoding="utf-8")
        (root / "suite" / "index.json").write_text("{}", encoding="utf-8")

    def test_counts_cases_by_revision_and_ignores_indexes(self) -> None:
        content = {
            "test_b": {
                "post": {
                    "Prague": [{"indexes": {"data": 0, "gas": 0, "value": 0}}]
                }
            },
            "test_a": {
                "post": {
                    "Frontier": [{"indexes": {"data": 0, "gas": 0, "value": 0}}],
                    "Osaka": [
                        {"indexes": {"data": 0, "gas": 0, "value": 0}},
                        {"indexes": {"data": 1, "gas": 0, "value": 0}},
                    ],
                }
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_fixture(root, content)
            manifest = build_manifest(
                root,
                release="v5.4.0",
                asset="fixtures_develop.tar.gz",
                url="https://example.test/fixtures_develop.tar.gz",
                sha256="a" * 64,
                required_revisions=("Frontier", "Prague", "Osaka"),
            )

        inventory = manifest["inventory"]
        self.assertEqual(inventory["json_files"], 1)
        self.assertEqual(inventory["tests"], 2)
        self.assertEqual(inventory["cases"], 4)
        self.assertEqual(
            {entry["name"]: entry["cases"] for entry in inventory["revisions"]},
            {"Frontier": 1, "Osaka": 2, "Prague": 1},
        )
        self.assertEqual(len(inventory["case_set_sha256"]), 64)

    def test_case_set_hash_is_independent_of_json_object_order(self) -> None:
        first = {
            "test": {
                "post": {
                    "Osaka": [
                        {
                            "hash": "0x01",
                            "indexes": {"value": 0, "gas": 0, "data": 0},
                        }
                    ]
                }
            }
        }
        second = {
            "test": {
                "post": {
                    "Osaka": [
                        {
                            "indexes": {"data": 0, "gas": 0, "value": 0},
                            "hash": "0x01",
                        }
                    ]
                }
            }
        }

        hashes = []
        for content in (first, second):
            with tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                self.write_fixture(root, content)
                manifest = build_manifest(
                    root,
                    release="v5.4.0",
                    asset="fixtures_develop.tar.gz",
                    url="https://example.test/fixtures_develop.tar.gz",
                    sha256="b" * 64,
                    required_revisions=("Osaka",),
                )
                hashes.append(manifest["inventory"]["case_set_sha256"])

        self.assertEqual(hashes[0], hashes[1])

    def test_rejects_missing_required_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_fixture(root, {"test": {"post": {"Prague": [{}]}}})

            with self.assertRaisesRegex(ValueError, "Osaka"):
                build_manifest(
                    root,
                    release="v5.4.0",
                    asset="fixtures_develop.tar.gz",
                    url="https://example.test/fixtures_develop.tar.gz",
                    sha256="c" * 64,
                    required_revisions=("Prague", "Osaka"),
                )

    def test_rejects_unexpected_case_set_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_fixture(root, {"test": {"post": {"Osaka": [{}]}}})

            with self.assertRaisesRegex(ValueError, "case-set SHA-256"):
                build_manifest(
                    root,
                    release="v5.4.0",
                    asset="fixtures_develop.tar.gz",
                    url="https://example.test/fixtures_develop.tar.gz",
                    sha256="d" * 64,
                    required_revisions=("Osaka",),
                    expected_case_set_sha256="0" * 64,
                )


if __name__ == "__main__":
    unittest.main()
