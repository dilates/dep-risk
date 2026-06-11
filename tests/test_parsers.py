from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from dep_risk.parsers.cargo import parse_cargo_toml, parse_cargo_lock
from dep_risk.parsers.npm import parse_package_json, parse_package_lock
from dep_risk.parsers.pip import parse_requirements_txt, parse_pipfile, parse_pyproject_toml

FIXTURES = Path(__file__).parent / "fixtures"


class TestNpmParser:
    def test_parse_package_json_deps(self):
        deps = parse_package_json(FIXTURES / "package.json")
        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names
        assert "axios" in names

    def test_parse_package_json_dev_deps(self):
        deps = parse_package_json(FIXTURES / "package.json")
        dev_names = {d.name for d in deps if d.is_dev}
        assert "jest" in dev_names
        assert "eslint" in dev_names

    def test_parse_package_json_ecosystem(self):
        deps = parse_package_json(FIXTURES / "package.json")
        assert all(d.ecosystem == "npm" for d in deps)

    def test_parse_package_json_missing_file(self):
        deps = parse_package_json(Path("/nonexistent/package.json"))
        assert deps == []

    def test_parse_package_lock_v1(self):
        lock_data = {
            "lockfileVersion": 1,
            "dependencies": {
                "express": {"version": "4.18.2", "dev": False},
                "jest": {"version": "29.5.0", "dev": True},
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(lock_data, f)
            tmp = Path(f.name)
        try:
            deps = parse_package_lock(tmp)
            names = {d.name for d in deps}
            assert "express" in names
            assert "jest" in names
        finally:
            tmp.unlink()

    def test_parse_package_lock_v2(self):
        lock_data = {
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "test-project"},
                "node_modules/express": {"name": "express", "version": "4.18.2"},
                "node_modules/jest": {"name": "jest", "version": "29.5.0", "dev": True},
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(lock_data, f)
            tmp = Path(f.name)
        try:
            deps = parse_package_lock(tmp)
            names = {d.name for d in deps}
            assert "express" in names
            assert "jest" in names
        finally:
            tmp.unlink()

    def test_version_range_stripped(self):
        deps = parse_package_json(FIXTURES / "package.json")
        express = next((d for d in deps if d.name == "express"), None)
        assert express is not None
        assert express.version_spec == "^4.18.2"
        assert express.version == "4.18.2"


class TestPipParser:
    def test_parse_requirements_txt(self):
        deps = parse_requirements_txt(FIXTURES / "requirements.txt")
        names = {d.name for d in deps}
        assert "requests" in names
        assert "numpy" in names
        assert "flask" in names

    def test_pinned_version(self):
        deps = parse_requirements_txt(FIXTURES / "requirements.txt")
        req = next((d for d in deps if d.name == "requests"), None)
        assert req is not None
        assert req.version == "2.31.0"

    def test_git_url_flagged(self):
        deps = parse_requirements_txt(FIXTURES / "requirements.txt")
        git_deps = [d for d in deps if d.is_git_dep]
        assert len(git_deps) >= 1
        assert git_deps[0].is_git_dep is True

    def test_extras_parsed(self):
        deps = parse_requirements_txt(FIXTURES / "requirements.txt")
        pillow = next((d for d in deps if d.name == "pillow"), None)
        assert pillow is not None
        assert "jpeg" in pillow.extras

    def test_comments_and_blanks_ignored(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("# comment\n\nrequests==2.0\n")
            tmp = Path(f.name)
        try:
            deps = parse_requirements_txt(tmp)
            assert len(deps) == 1
            assert deps[0].name == "requests"
        finally:
            tmp.unlink()

    def test_parse_pyproject_toml_project(self):
        content = b"""
[project]
name = "myapp"
dependencies = [
    "requests>=2.28",
    "click>=8.0",
    "flask==2.3.0",
]
[project.optional-dependencies]
dev = ["pytest>=7.0"]
"""
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="wb", delete=False) as f:
            f.write(content)
            tmp = Path(f.name)
        try:
            deps = parse_pyproject_toml(tmp)
            names = {d.name for d in deps}
            assert "requests" in names
            assert "click" in names
            assert "flask" in names
            assert "pytest" in names
        finally:
            tmp.unlink()

    def test_parse_pipfile(self):
        content = b"""
[packages]
requests = "*"
flask = ">=2.0"

[dev-packages]
pytest = ">=7.0"
"""
        with tempfile.NamedTemporaryFile(suffix="Pipfile", mode="wb", delete=False) as f:
            f.write(content)
            tmp = Path(f.name)
        try:
            deps = parse_pipfile(tmp)
            names = {d.name for d in deps}
            assert "requests" in names
            assert "flask" in names
            assert "pytest" in names
            dev = [d for d in deps if d.is_dev]
            assert any(d.name == "pytest" for d in dev)
        finally:
            tmp.unlink()

    def test_missing_file(self):
        assert parse_requirements_txt(Path("/nonexistent.txt")) == []


class TestCargoParser:
    def test_parse_cargo_toml(self):
        deps = parse_cargo_toml(FIXTURES / "Cargo.toml")
        names = {d.name for d in deps}
        assert "serde" in names
        assert "tokio" in names
        assert "anyhow" in names

    def test_dev_deps_flagged(self):
        deps = parse_cargo_toml(FIXTURES / "Cargo.toml")
        dev = [d for d in deps if d.is_dev]
        assert any(d.name == "criterion" for d in dev)

    def test_ecosystem_set(self):
        deps = parse_cargo_toml(FIXTURES / "Cargo.toml")
        assert all(d.ecosystem == "cargo" for d in deps)

    def test_path_dep_skipped(self):
        content = b"""
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
local-crate = { path = "../local-crate" }
"""
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="wb", delete=False) as f:
            f.write(content)
            tmp = Path(f.name)
        try:
            deps = parse_cargo_toml(tmp)
            local = [d for d in deps if d.is_path_dep]
            assert any(d.name == "local-crate" for d in local)
        finally:
            tmp.unlink()

    def test_parse_cargo_lock(self):
        content = b"""
[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abcdef1234567890"

[[package]]
name = "tokio"
version = "1.34.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fedcba0987654321"
"""
        with tempfile.NamedTemporaryFile(suffix=".lock", mode="wb", delete=False) as f:
            f.write(content)
            tmp = Path(f.name)
        try:
            deps = parse_cargo_lock(tmp)
            names = {d.name for d in deps}
            assert "serde" in names
            assert "tokio" in names
            serde = next(d for d in deps if d.name == "serde")
            assert serde.checksum == "abcdef1234567890"
        finally:
            tmp.unlink()

    def test_missing_file(self):
        assert parse_cargo_toml(Path("/nonexistent/Cargo.toml")) == []
