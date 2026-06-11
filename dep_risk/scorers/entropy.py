from __future__ import annotations

import math
import re
from typing import Any

from dep_risk.scorers.base import Dependency, RiskScore

_WORD_NUMBER_RE = re.compile(r"^([a-z]+)(\d+)$")
_MIXED_CASE_NUMBER_RE = re.compile(r"[A-Z].*\d|\d.*[A-Z]")


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


class EntropyScorer:
    name = "entropy"
    weight = 0.05

    async def score(
        self,
        dep: Dependency,
        registry_data: Any,
        github_data: Any,
    ) -> RiskScore:
        name = dep.name.lower()
        clean_name = re.sub(r"[@/]", "", name)

        score = 0.0
        findings: list[str] = []
        details: list[str] = []
        evidence: dict[str, Any] = {}

        entropy = _shannon_entropy(clean_name)
        evidence["name_entropy"] = round(entropy, 3)
        evidence["name_length"] = len(clean_name)

        if entropy > 3.8:
            score += 30
            findings.append(f"High name entropy ({entropy:.2f} bits/char) — random-looking name")
            details.append(f"Shannon entropy of package name is {entropy:.2f}, suggesting a randomly generated name.")

        if len(clean_name) <= 2:
            score += 15
            findings.append(f"Very short package name '{name}' — high squatting risk")
            details.append("Extremely short names are high-value squatting targets.")

        if _MIXED_CASE_NUMBER_RE.search(clean_name):
            score += 20
            findings.append("Mixed case with numbers in unusual pattern")
            details.append("Package name combines uppercase and numbers in a way that looks obfuscated.")

        wn_match = _WORD_NUMBER_RE.match(clean_name)
        if wn_match:
            word, number = wn_match.group(1), wn_match.group(2)
            if len(word) > 3:
                score += 25
                findings.append(f"Common word with number appended: '{word}' + '{number}'")
                details.append(f"Pattern '{clean_name}' looks like a numbered variant of '{word}' — possible squatting.")
                evidence["word_number_pattern"] = {"word": word, "number": number}

        score = min(100.0, score)
        finding = findings[0] if findings else "Package name appears normal"
        detail = "\n".join(details) if details else "No name entropy concerns detected."

        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )
