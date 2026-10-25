#!/usr/bin/env python3
"""Copy an exact public-source allowlist into a new directory without Git history."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat


FORBIDDEN_PARTS = {".git", ".runtime", ".venv", ".aws", ".codex", ".agents",
                   "__pycache__", ".pytest_cache", ".ruff_cache", "evidence",
                   "release-artifacts", "codebuild-arm64-proposal"}
FORBIDDEN_PREFIXES = ("deploy/iam/", "deploy/iam-resolved-proposal/")
FORBIDDEN_FILES = {"RECOVERY_STATUS.md", "deploy/pilot-template.json",
                   "deploy/review-package.json", "deploy/local-image-evidence.json"}
PUBLIC_SKILL_FILES = {
    ".agents/skills/secure-agent-controller/SKILL.md",
    ".agents/skills/secure-agent-controller/agents/openai.yaml",
}


def export_public(source: Path, manifest: Path, output: Path) -> dict:
    source = source.resolve(strict=True)
    if not output.is_absolute():
        raise ValueError("new_absolute_output_outside_source_required")
    output = output.parent.resolve(strict=True) / output.name
    if output.exists() or output.is_symlink() or source == output or source in output.parents:
        raise ValueError("new_absolute_output_outside_source_required")
    definition = json.loads(manifest.read_text())
    if (type(definition) is not dict or set(definition) != {"schema_version", "files"}
            or definition["schema_version"] != 1 or type(definition["files"]) is not list
            or not definition["files"] or any(type(name) is not str for name in definition["files"])
            or definition["files"] != sorted(set(definition["files"]))):
        raise ValueError("exact_sorted_unique_public_allowlist_required")
    payload = []
    for name in definition["files"]:
        relative = PurePosixPath(name)
        if (relative.is_absolute() or name != relative.as_posix() or ".." in relative.parts
                or not relative.parts or any(
                    part in FORBIDDEN_PARTS
                    and not (part == ".agents" and name in PUBLIC_SKILL_FILES)
                    for part in relative.parts)
                or name in FORBIDDEN_FILES or name.startswith(FORBIDDEN_PREFIXES)
                or any(part == ".env" or part.endswith((".sqlite", ".sqlite3", ".db", ".pyc",
                                                        ".pem", ".key", ".p12", ".pfx"))
                       for part in relative.parts)):
            raise ValueError("private_or_unsafe_public_path")
        path = source
        for part in relative.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError("symlinks_not_allowed_in_public_export")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2 * 1024 * 1024:
            raise ValueError("bounded_regular_source_file_required")
        data = path.read_bytes()
        if b"\0" in data:
            raise ValueError("text_source_files_only")
        mode = 0o755 if metadata.st_mode & 0o111 else 0o644
        payload.append((name, data, mode))
    record = {"schema_version": 1, "files": [
        {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data, _ in payload]}
    output.mkdir(mode=0o755)
    for name, data, mode in payload:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(mode)
    (output / "PUBLIC_RELEASE_MANIFEST.json").write_text(json.dumps(record, indent=2) + "\n")
    return {"output": str(output), "source_files": len(payload), "git_history_exported": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "public-release-files.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = export_public(Path(__file__).resolve().parents[1], args.manifest, args.output)
    except (OSError, ValueError, TypeError):
        parser.exit(2, "Public export rejected: invalid allowlist, source or destination.\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
