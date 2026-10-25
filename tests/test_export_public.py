"""Public skill files are allowed without exposing other agent state."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.export_public import export_public


SKILL_FILES = (
    ".agents/skills/secure-agent-controller/SKILL.md",
    ".agents/skills/secure-agent-controller/agents/openai.yaml",
)


class PublicSkillExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.manifest = self.root / "allowlist.json"
        self.output = self.root / "export"

    def write_manifest(self, paths):
        self.manifest.write_text(json.dumps({"schema_version": 1, "files": sorted(paths)}))

    def test_two_explicit_skill_files_export(self):
        for name in SKILL_FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("public skill fixture\n")
        self.write_manifest(SKILL_FILES)

        result = export_public(self.source, self.manifest, self.output)

        self.assertEqual(result["source_files"], 2)
        self.assertFalse(result["git_history_exported"])
        for name in SKILL_FILES:
            self.assertEqual((self.output / name).read_text(), "public skill fixture\n")
        exported_manifest = json.loads((self.output / "PUBLIC_RELEASE_MANIFEST.json").read_text())
        self.assertEqual([entry["path"] for entry in exported_manifest["files"]], list(SKILL_FILES))

    def test_other_agent_paths_and_forbidden_components_are_rejected(self):
        for name in (
            ".agents/skills/other/SKILL.md",
            ".agents/skills/secure-agent-controller/private.md",
            ".agents/skills/secure-agent-controller/.aws/credentials",
            ".agents/skills/secure-agent-controller/../private.md",
            "nested/.agents/skills/secure-agent-controller/SKILL.md",
        ):
            with self.subTest(name=name):
                self.write_manifest([name])
                with self.assertRaisesRegex(ValueError, "private_or_unsafe_public_path"):
                    export_public(self.source, self.manifest, self.output)
                self.assertFalse(self.output.exists())

    def test_allowed_skill_path_still_rejects_symlink(self):
        target = self.root / "other-agents"
        target.mkdir()
        (self.source / ".agents").symlink_to(target, target_is_directory=True)
        self.write_manifest([SKILL_FILES[0]])

        with self.assertRaisesRegex(ValueError, "symlinks_not_allowed_in_public_export"):
            export_public(self.source, self.manifest, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
