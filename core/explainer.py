"""
EncryptedFlow AI - Explainability & Evidence Engine
Computes feature attributions against baseline benign distributions.
Translates mathematical anomalies into plain-English physical network evidence.
"""

from typing import Dict, List, Any
import numpy as np


class FlowExplainer:
    """
    Computes Z-score deviations of observed flow features against confirmed benign baselines.
    Outputs human-auditable physical evidence for flagged threat flows.
    """

    # Empirical baseline statistics for confirmed benign HTTPS/web traffic
    # Derived from benign network flow observations: (mean, std)
    BENIGN_BASELINES = {
        "mean_packet_size": (680.0, 220.0),
        "std_packet_size": (450.0, 150.0),
        "max_packet_size": (1420.0, 180.0),
        "min_packet_size": (54.0, 15.0),
        "mean_iat": (0.045, 0.035),          # ~45ms mean IAT
        "std_iat": (0.065, 0.045),           # Human jitter ~65ms
        "max_iat": (0.450, 0.300),           # Human think-time pause
        "duration": (0.850, 0.500),
        "fwd_bwd_packet_ratio": (0.65, 0.35), # Typically download-biased
        "fwd_bwd_byte_ratio": (0.15, 0.12),   # Rarely exceeds 0.5 in browsing
        "packet_rate": (45.0, 30.0),
        "byte_rate": (35000.0, 25000.0),
        "mean_tcp_window": (48000.0, 16000.0)
    }

    # Human-readable diagnostic templates for physical network indicators
    EVIDENCE_TEMPLATES = {
        "fwd_bwd_byte_ratio": (
            "Abnormal upstream upload bias ({val:.1f}x forward/backward ratio vs ~0.15x normal baseline)"
        ),
        "fwd_bwd_packet_ratio": (
            "Severe directional asymmetry ({val:.1f}x forward-to-backward packet frequency)"
        ),
        "mean_iat": (
            "Unusually rapid machine-gun packet intervals (Mean IAT: {val_ms:.2f}ms vs ~45ms normal)"
        ),
        "std_iat": (
            "Near-zero timing jitter (StdDev: {val_ms:.2f}ms) indicating automated programmatic transmission"
        ),
        "mean_packet_size": (
            "Anomalous packet sizing (Mean: {val:.0f} bytes) characteristic of uniform payload streaming"
        ),
        "packet_rate": (
            "High-frequency volumetric burst ({val:.0f} pkts/sec exceeding typical human session rates)"
        ),
        "byte_rate": (
            "High-bandwidth egress transfer ({val_kbps:.1f} KB/s sustained upload velocity)"
        ),
        "max_packet_size": (
            "Continuous full-MTU packet saturation (Max size: {val:.0f} bytes)"
        ),
        "min_packet_size": (
            "Train of tiny zero-payload probe packets (Min size: {val:.0f} bytes)"
        )
    }

    def __init__(self, z_threshold: float = 2.0):
        self.z_threshold = z_threshold

    def explain(self, features: Dict[str, float], predicted_class: str) -> List[str]:
        """
        Analyzes the 13 feature dimensions, computes statistical deviation from benign baseline,
        and returns the top-3 contributing physical network evidence statements.
        """
        # If predicted benign, no threat evidence needed
        if predicted_class in ("BENIGN_WEB", "BENIGN_STREAM", "BENIGN"):
            return ["Traffic dynamics conform to baseline human interactive browsing distributions."]

        anomalies = []

        for feat_name, val in features.items():
            if feat_name not in self.BENIGN_BASELINES:
                continue

            base_mean, base_std = self.BENIGN_BASELINES[feat_name]
            safe_std = max(base_std, 1e-5)
            z_score = (val - base_mean) / safe_std

            # We care about deviations (positive or negative depending on feature)
            abs_z = abs(z_score)
            if abs_z >= self.z_threshold:
                anomalies.append({
                    "feature": feat_name,
                    "value": val,
                    "z_score": z_score,
                    "abs_z": abs_z
                })

        # Sort by statistical deviation magnitude (highest first)
        anomalies.sort(key=lambda x: x["abs_z"], reverse=True)

        evidence_list = []
        for item in anomalies[:3]:
            feat = item["feature"]
            val = item["value"]
            if feat in self.EVIDENCE_TEMPLATES:
                stmt = self.EVIDENCE_TEMPLATES[feat].format(
                    val=val,
                    val_ms=val * 1000.0,
                    val_kbps=val / 1024.0
                )
                evidence_list.append(stmt)

        # Fallback if no individual feature crossed extreme threshold
        if not evidence_list:
            evidence_list.append(
                f"Multi-variate temporal signature matches {predicted_class} attack profile."
            )

        return evidence_list
