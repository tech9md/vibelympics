"""ML-based anomaly detection analyzer."""
import math
import re
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class MLAnomalyAnalyzer(BaseAnalyzer):
    """
    Analyze packages using statistical anomaly detection.

    Uses feature extraction and threshold-based scoring to detect
    packages that deviate from typical patterns.

    No external ML libraries required - uses pure Python statistics.
    """

    category = "ml_anomaly"
    weight = 0.03

    # Feature thresholds based on analysis of popular packages
    # Format: (min_normal, max_normal, weight)
    FEATURE_THRESHOLDS = {
        "name_length": (2, 40, 0.5),
        "name_entropy": (2.0, 4.5, 1.0),
        "name_digit_ratio": (0.0, 0.3, 0.8),
        "description_length": (10, 1000, 0.6),
        "has_homepage": (1, 1, 0.3),  # Should have homepage
        "has_repository": (1, 1, 0.4),  # Should have repo
        "has_license": (1, 1, 0.5),  # Should have license
        "maintainer_count": (1, 10, 0.4),
        "dependency_count": (0, 50, 0.3),
        "classifier_count": (1, 20, 0.4),
        "version_count": (1, 200, 0.2),
        "readme_length": (100, 50000, 0.5),
        "has_author_email": (1, 1, 0.3),
    }

    # Suspicious feature combinations
    SUSPICIOUS_COMBINATIONS = [
        # (condition_function, severity, title, description)
        (
            lambda f: f["name_entropy"] > 4.0 and f["description_length"] < 50,
            SeverityLevel.MEDIUM,
            "High-entropy name with minimal description",
            "Package name appears random and has very little documentation.",
        ),
        (
            lambda f: f["version_count"] > 50 and f["has_repository"] == 0,
            SeverityLevel.MEDIUM,
            "Many versions but no repository",
            "Package has many versions but no source repository link.",
        ),
        (
            lambda f: f["dependency_count"] == 0 and f["classifier_count"] > 5,
            SeverityLevel.LOW,
            "No dependencies but many classifiers",
            "Package claims broad functionality but has no dependencies.",
        ),
        (
            lambda f: f["maintainer_count"] == 0 and f["version_count"] > 10,
            SeverityLevel.MEDIUM,
            "No maintainer info with many versions",
            "Package has many versions but no maintainer information.",
        ),
        (
            lambda f: f["name_digit_ratio"] > 0.4,
            SeverityLevel.MEDIUM,
            "Package name mostly digits",
            "Package name contains unusually high proportion of numbers.",
        ),
    ]

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package for statistical anomalies."""
        findings = []

        # 1. Extract features
        features = self._extract_features(package_name, package_metadata)

        # 2. Calculate anomaly scores for each feature
        feature_scores, anomalies = self._calculate_feature_scores(features)

        # 3. Generate findings for anomalous features
        for feature_name, (score, direction) in anomalies.items():
            if score > 30:  # Threshold for reporting
                severity = self._score_to_severity(score)
                findings.append(
                    Finding(
                        category=self.category,
                        severity=severity,
                        title=f"Anomalous {self._format_feature_name(feature_name)}",
                        description=self._get_anomaly_description(feature_name, features[feature_name], direction),
                        metadata={
                            "feature": feature_name,
                            "value": features[feature_name],
                            "anomaly_score": score,
                            "direction": direction,
                        },
                    )
                )

        # 4. Check for suspicious combinations
        combination_findings = self._check_combinations(features)
        findings.extend(combination_findings)

        # 5. Calculate overall anomaly score
        overall_score = self._calculate_overall_score(feature_scores)

        if overall_score > 50:
            findings.append(
                Finding(
                    category=self.category,
                    severity=self._score_to_severity(overall_score),
                    title="Overall anomaly detected",
                    description=f"Package has an overall anomaly score of {overall_score:.1f}/100, indicating unusual characteristics.",
                    metadata={"overall_score": overall_score, "features": features},
                )
            )

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "features": features,
                "feature_scores": feature_scores,
                "overall_anomaly_score": overall_score,
            },
        )

    def _extract_features(
        self, package_name: str, metadata: Dict[str, Any]
    ) -> Dict[str, float]:
        """Extract numerical features from package."""
        summary = metadata.get("summary") or ""
        description = metadata.get("description") or ""
        classifiers = metadata.get("classifiers") or []
        requires_dist = metadata.get("requires_dist") or []
        maintainers = metadata.get("maintainers") or []
        releases = metadata.get("releases") or {}

        features = {
            # Name features
            "name_length": len(package_name),
            "name_entropy": self._calculate_entropy(package_name),
            "name_digit_ratio": sum(c.isdigit() for c in package_name) / max(len(package_name), 1),

            # Documentation features
            "description_length": len(summary),
            "readme_length": len(description),

            # Metadata completeness
            "has_homepage": 1 if metadata.get("home_page") else 0,
            "has_repository": 1 if metadata.get("project_url") else 0,
            "has_license": 1 if metadata.get("license") else 0,
            "has_author_email": 1 if metadata.get("author_email") else 0,

            # Counts
            "maintainer_count": len(maintainers) + (1 if metadata.get("author") else 0),
            "dependency_count": len(requires_dist),
            "classifier_count": len(classifiers),
            "version_count": len(releases),
        }

        return features

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0

        freq = Counter(s.lower())
        probs = [count / len(s) for count in freq.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def _calculate_feature_scores(
        self, features: Dict[str, float]
    ) -> Tuple[Dict[str, float], Dict[str, Tuple[float, str]]]:
        """Calculate anomaly scores for each feature."""
        scores = {}
        anomalies = {}

        for feature_name, value in features.items():
            if feature_name not in self.FEATURE_THRESHOLDS:
                continue

            min_val, max_val, weight = self.FEATURE_THRESHOLDS[feature_name]

            if value < min_val:
                # Below minimum
                if min_val > 0:
                    deviation = (min_val - value) / min_val
                else:
                    deviation = abs(min_val - value)
                score = min(100, deviation * 100 * weight)
                direction = "low"
            elif value > max_val:
                # Above maximum
                deviation = (value - max_val) / max(max_val, 1)
                score = min(100, deviation * 100 * weight)
                direction = "high"
            else:
                # Within normal range
                score = 0
                direction = "normal"

            scores[feature_name] = score
            if score > 20:  # Only track significant anomalies
                anomalies[feature_name] = (score, direction)

        return scores, anomalies

    def _calculate_overall_score(self, feature_scores: Dict[str, float]) -> float:
        """Calculate weighted overall anomaly score."""
        if not feature_scores:
            return 0.0

        total_weight = 0
        weighted_sum = 0

        for feature_name, score in feature_scores.items():
            if feature_name in self.FEATURE_THRESHOLDS:
                weight = self.FEATURE_THRESHOLDS[feature_name][2]
                weighted_sum += score * weight
                total_weight += weight

        if total_weight > 0:
            return weighted_sum / total_weight

        return 0.0

    def _check_combinations(self, features: Dict[str, float]) -> List[Finding]:
        """Check for suspicious feature combinations."""
        findings = []

        for condition, severity, title, description in self.SUSPICIOUS_COMBINATIONS:
            try:
                if condition(features):
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=severity,
                            title=title,
                            description=description,
                            metadata={"features": features},
                        )
                    )
            except (KeyError, ZeroDivisionError):
                continue

        return findings

    def _score_to_severity(self, score: float) -> SeverityLevel:
        """Convert anomaly score to severity level."""
        if score >= 80:
            return SeverityLevel.HIGH
        elif score >= 60:
            return SeverityLevel.MEDIUM
        elif score >= 40:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def _format_feature_name(self, name: str) -> str:
        """Format feature name for display."""
        return name.replace("_", " ").title()

    def _get_anomaly_description(
        self, feature_name: str, value: float, direction: str
    ) -> str:
        """Generate description for an anomalous feature."""
        descriptions = {
            "name_length": {
                "low": f"Package name is unusually short ({value} chars).",
                "high": f"Package name is unusually long ({value} chars).",
            },
            "name_entropy": {
                "low": f"Package name has very low entropy ({value:.2f}), appears repetitive.",
                "high": f"Package name has high entropy ({value:.2f}), appears random.",
            },
            "name_digit_ratio": {
                "high": f"Package name is {value*100:.0f}% digits, which is unusual.",
            },
            "description_length": {
                "low": f"Package has very short or no description ({value} chars).",
                "high": f"Package description is unusually long ({value} chars).",
            },
            "has_homepage": {
                "low": "Package has no homepage URL.",
            },
            "has_repository": {
                "low": "Package has no source repository link.",
            },
            "has_license": {
                "low": "Package has no license specified.",
            },
            "maintainer_count": {
                "low": "Package has no maintainer information.",
                "high": f"Package has unusually many maintainers ({int(value)}).",
            },
            "dependency_count": {
                "high": f"Package has many dependencies ({int(value)}).",
            },
            "classifier_count": {
                "low": "Package has no classifiers.",
                "high": f"Package has unusually many classifiers ({int(value)}).",
            },
            "version_count": {
                "low": "Package has only one version.",
                "high": f"Package has unusually many versions ({int(value)}).",
            },
            "readme_length": {
                "low": f"Package has very short README ({value} chars).",
                "high": f"Package has unusually long README ({value} chars).",
            },
        }

        feature_desc = descriptions.get(feature_name, {})
        return feature_desc.get(direction, f"Feature {feature_name} has unusual value: {value}")
