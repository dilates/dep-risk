from __future__ import annotations

import math
import re
from typing import Any

from dep_risk.scorers.base import Dependency, RiskScore

_DOWNLOAD_RE = re.compile(r"\b(curl|wget|fetch|http\.get|https\.get|urllib|requests\.get)\b", re.IGNORECASE)
_EVAL_RE = re.compile(r"\b(eval|exec|__import__)\s*\(", re.IGNORECASE)
_SPAWN_RE = re.compile(r"\bspawn\s*\(|child_process|execSync|spawnSync", re.IGNORECASE)
_ENV_RE = re.compile(r"\bprocess\.env\b", re.IGNORECASE)
_NETWORK_PY_RE = re.compile(r"\b(urllib|requests|socket|http\.client|httplib)\b", re.IGNORECASE)
_OBFUSCATION_ENTROPY_THRESHOLD = 4.5
_CURL_WGET_RE = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
_SH_RE = re.compile(r"\b(sh|bash|cmd)\b", re.IGNORECASE)
_BINARY_RE = re.compile(r"download|binary|\.exe|\.dll|\.so\b", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


class InstallScriptScorer:
    name = "install_script"
    weight = 0.30

    async def score(
        self,
        dep: Dependency,
        registry_data: Any,
        github_data: Any,
    ) -> RiskScore:
        score = 0.0
        findings: list[str] = []
        details: list[str] = []
        evidence: dict[str, Any] = {}

        if dep.ecosystem == "npm":
            score, findings, details, evidence = _score_npm(registry_data)
        elif dep.ecosystem == "pip":
            score, findings, details, evidence = _score_pip(registry_data)
        elif dep.ecosystem == "cargo":
            score, findings, details, evidence = _score_cargo(registry_data)
        elif dep.ecosystem == "aur":
            score, findings, details, evidence = _score_aur(registry_data)

        score = min(100.0, score)
        finding = findings[0] if findings else "No dangerous install scripts detected"
        detail = "\n".join(details) if details else "No install-time code execution detected."

        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )


def _score_npm(data: Any) -> tuple[float, list[str], list[str], dict[str, Any]]:
    from dep_risk.sources.npm_registry import NpmPackageData
    score = 0.0
    findings: list[str] = []
    details: list[str] = []
    evidence: dict[str, Any] = {}

    if not isinstance(data, NpmPackageData):
        return score, findings, details, evidence

    latest_ver = data.version_data.get(data.latest_version)
    if not latest_ver:
        return score, findings, details, evidence

    scripts = latest_ver.scripts
    dangerous_hooks = {"preinstall", "postinstall", "install", "prepare"}
    found_hooks = {k: v for k, v in scripts.items() if k in dangerous_hooks}
    evidence["scripts"] = found_hooks

    if found_hooks:
        score += 40
        findings.append(f"Has install hook: {', '.join(found_hooks.keys())}")
        details.append(f"Install scripts present: {found_hooks}")

    for hook_name, script_content in found_hooks.items():
        if _DOWNLOAD_RE.search(script_content):
            score += 70
            findings.append(f"Downloads during {hook_name} — network call detected")
            details.append(f"{hook_name} script makes network requests: {script_content[:200]}")
            evidence[f"{hook_name}_downloads"] = True

        if _EVAL_RE.search(script_content):
            score += 60
            findings.append(f"Dynamic code execution in {hook_name} script")
            details.append(f"eval/exec pattern in {hook_name}: {script_content[:200]}")
            evidence[f"{hook_name}_eval"] = True

        if _SPAWN_RE.search(script_content):
            score += 60
            findings.append(f"Process spawning in {hook_name} script")
            details.append(f"spawn/exec pattern in {hook_name}")
            evidence[f"{hook_name}_spawn"] = True

        if _ENV_RE.search(script_content):
            score += 30
            findings.append(f"Reads environment variables during {hook_name}")
            details.append(f"process.env accessed in {hook_name}")
            evidence[f"{hook_name}_env_read"] = True

        entropy = _shannon_entropy(script_content)
        if entropy > _OBFUSCATION_ENTROPY_THRESHOLD:
            score += 80
            findings.append(f"Obfuscated {hook_name} script (entropy {entropy:.2f})")
            details.append(f"High entropy script content suggests obfuscation (entropy={entropy:.2f})")
            evidence[f"{hook_name}_entropy"] = entropy

    return score, findings, details, evidence


def _score_pip(data: Any) -> tuple[float, list[str], list[str], dict[str, Any]]:
    from dep_risk.sources.pypi import PypiPackageData
    score = 0.0
    findings: list[str] = []
    details: list[str] = []
    evidence: dict[str, Any] = {}

    if not isinstance(data, PypiPackageData):
        return score, findings, details, evidence

    has_binary_dist = False
    has_source_dist = False

    for ver, vdata in data.version_data.items():
        if vdata.packagetype == "bdist_wheel":
            has_binary_dist = True
        if vdata.packagetype == "sdist":
            has_source_dist = True

    if has_binary_dist and not has_source_dist:
        score += 50
        findings.append("Only binary wheels available — no source distribution")
        details.append("Package only ships precompiled binaries (no sdist), cannot inspect source code.")
        evidence["binary_only"] = True

    return score, findings, details, evidence


_PKGBUILD_SKIP_CHECKSUM_RE = re.compile(r"sha\w+sums\s*=\s*\(\s*['\"]SKIP['\"]", re.IGNORECASE)
_PKGBUILD_BASE64_RE = re.compile(r"\|\s*base64\s*(-d|--decode)", re.IGNORECASE)
_PKGBUILD_OUTSIDE_PKGDIR_RE = re.compile(r"\b(cp|install|mv)\b[^#\n]*/(?!usr|etc|opt|srv|var)\w", re.IGNORECASE)


def _score_aur(data: Any) -> tuple[float, list[str], list[str], dict[str, Any]]:
    from dep_risk.sources.aur import AurPackageData
    score = 0.0
    findings: list[str] = []
    details: list[str] = []
    evidence: dict[str, Any] = {}

    if not isinstance(data, AurPackageData):
        return score, findings, details, evidence

    pkgbuild = data.pkgbuild
    if not pkgbuild:
        score += 20
        findings.append("PKGBUILD could not be fetched — cannot inspect install script")
        details.append("Unable to retrieve PKGBUILD from AUR for static analysis.")
        evidence["pkgbuild_missing"] = True
        return score, findings, details, evidence

    evidence["pkgbuild_length"] = len(pkgbuild)

    if _DOWNLOAD_RE.search(pkgbuild):
        score += 40
        findings.append("PKGBUILD makes network requests at build/install time")
        details.append("PKGBUILD contains curl/wget/fetch — downloads content at build time.")
        evidence["pkgbuild_downloads"] = True

    if _EVAL_RE.search(pkgbuild):
        score += 60
        findings.append("PKGBUILD uses eval/exec (dynamic code execution)")
        details.append("PKGBUILD contains eval or exec patterns — high risk of code injection.")
        evidence["pkgbuild_eval"] = True

    if _PKGBUILD_BASE64_RE.search(pkgbuild):
        score += 70
        findings.append("PKGBUILD decodes base64 at build time — possible obfuscated payload")
        details.append("PKGBUILD pipes output through base64 --decode, a common obfuscation technique.")
        evidence["pkgbuild_base64"] = True

    if _PKGBUILD_SKIP_CHECKSUM_RE.search(pkgbuild):
        score += 50
        findings.append("PKGBUILD skips checksum validation (SKIP)")
        details.append("sha256sums or similar set to 'SKIP' — source integrity not verified.")
        evidence["pkgbuild_skip_checksum"] = True

    entropy = _shannon_entropy(pkgbuild)
    if entropy > _OBFUSCATION_ENTROPY_THRESHOLD:
        score += 50
        findings.append(f"High-entropy PKGBUILD content (entropy {entropy:.2f}) — possible obfuscation")
        details.append(f"Shannon entropy {entropy:.2f} bits/char suggests obfuscated content in PKGBUILD.")
        evidence["pkgbuild_entropy"] = entropy

    return score, findings, details, evidence


def _score_cargo(data: Any) -> tuple[float, list[str], list[str], dict[str, Any]]:
    from dep_risk.sources.crates import CrateData
    score = 0.0
    findings: list[str] = []
    details: list[str] = []
    evidence: dict[str, Any] = {}

    if not isinstance(data, CrateData):
        return score, findings, details, evidence

    return score, findings, details, evidence
