"""
EncryptedFlow AI - Core Feature Extractor
Extracts 13 observable, payload-agnostic metadata features from the first N packets of a flow.
Zero payload inspection - only physical transport/link layer dynamics.
"""

import numpy as np
from typing import List, Dict, Any
from core.flow_tracker import PacketMetadata


class FeatureExtractor:
    """
    Computes 13 temporal, volumetric, and directional features from an early-flow packet window.
    Designed for early threat classification (e.g., N = 5, 10, 20, 50 packets).
    """

    FEATURE_NAMES = [
        "mean_packet_size",
        "std_packet_size",
        "max_packet_size",
        "min_packet_size",
        "mean_iat",
        "std_iat",
        "max_iat",
        "duration",
        "fwd_bwd_packet_ratio",
        "fwd_bwd_byte_ratio",
        "packet_rate",
        "byte_rate",
        "mean_tcp_window"
    ]

    def __init__(self, observation_window: int = 20):
        self.observation_window = observation_window

    def extract_features(self, packets: List[PacketMetadata]) -> Dict[str, float]:
        """
        Extracts tabular statistical features from a list of observed packets.
        Returns a dictionary mapping feature names to numerical values.
        """
        if not packets:
            return {name: 0.0 for name in self.FEATURE_NAMES}

        # Truncate to observation window
        window = packets[:self.observation_window]
        n = len(window)

        # 1. Packet Sizes
        sizes = np.array([p.size for p in window], dtype=np.float32)
        mean_size = float(np.mean(sizes))
        std_size = float(np.std(sizes)) if n > 1 else 0.0
        max_size = float(np.max(sizes))
        min_size = float(np.min(sizes))

        # 2. Inter-Arrival Times (IAT)
        timestamps = np.array([p.timestamp for p in window], dtype=np.float64)
        if n > 1:
            iats = np.diff(timestamps)
            # Clip negative IATs in case of out-of-order capture timestamps
            iats = np.maximum(iats, 0.0)
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))
            max_iat = float(np.max(iats))
            duration = float(timestamps[-1] - timestamps[0])
        else:
            mean_iat = 0.0
            std_iat = 0.0
            max_iat = 0.0
            duration = 0.001  # Minimum nominal duration to prevent division by zero

        # 3. Directional Ratios (+1: forward/client, -1: backward/server)
        fwd_packets = sum(1 for p in window if p.direction == 1)
        bwd_packets = sum(1 for p in window if p.direction == -1)
        fwd_bytes = sum(p.size for p in window if p.direction == 1)
        bwd_bytes = sum(p.size for p in window if p.direction == -1)

        fwd_bwd_packet_ratio = float(fwd_packets / max(bwd_packets, 1))
        fwd_bwd_byte_ratio = float(fwd_bytes / max(bwd_bytes, 1))

        # 4. Velocities (Rates)
        safe_duration = max(duration, 0.0001)
        packet_rate = float(n / safe_duration)
        byte_rate = float(np.sum(sizes) / safe_duration)

        # 5. TCP Window Dynamics
        windows = np.array([p.tcp_window for p in window], dtype=np.float32)
        mean_tcp_window = float(np.mean(windows))

        return {
            "mean_packet_size": mean_size,
            "std_packet_size": std_size,
            "max_packet_size": max_size,
            "min_packet_size": min_size,
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "max_iat": max_iat,
            "duration": duration,
            "fwd_bwd_packet_ratio": fwd_bwd_packet_ratio,
            "fwd_bwd_byte_ratio": fwd_bwd_byte_ratio,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "mean_tcp_window": mean_tcp_window
        }

    def extract_vector(self, packets: List[PacketMetadata]) -> np.ndarray:
        """Returns the 13 features as a 1D numpy array aligned with FEATURE_NAMES."""
        feat_dict = self.extract_features(packets)
        return np.array([feat_dict[k] for k in self.FEATURE_NAMES], dtype=np.float32)

    def extract_sequence(self, packets: List[PacketMetadata], pad_length: int = 20) -> np.ndarray:
        """
        Extracts temporal sequence matrix (length x features_per_packet) for 1D-CNN / BiLSTM.
        Each packet is represented by: [size, delta_t, direction, tcp_window]
        Pads with zeros if observed packets < pad_length.
        """
        window = packets[:pad_length]
        seq = []

        prev_time = window[0].timestamp if window else 0.0
        for p in window:
            delta_t = max(p.timestamp - prev_time, 0.0)
            prev_time = p.timestamp
            seq.append([
                float(p.size),
                float(delta_t),
                float(p.direction),
                float(p.tcp_window)
            ])

        # Zero-pad to fixed sequence length if needed
        while len(seq) < pad_length:
            seq.append([0.0, 0.0, 0.0, 0.0])

        return np.array(seq, dtype=np.float32)
