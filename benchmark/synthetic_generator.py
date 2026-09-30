"""
EncryptedFlow AI - Synthetic Ground-Truth Traffic Generator
Generates realistic transport-layer packet flows across 5 behavioral profiles:
- BENIGN_WEB: Human interactive browsing (bimodal sizes, human think-time pauses)
- BENIGN_STREAM: Continuous video streaming (steady MTU packets, uniform IAT)
- SCAN_RECON: Stealth port scanning (rapid-fire small probe packets, low IAT)
- DATA_EXFIL: Encrypted data theft (massive continuous upstream bursts)
- C2_BEACON: Botnet heartbeats (deterministic periodic clock-like intervals)
Supports adversarial traffic shaping (random padding and inter-packet jitter).
"""

import numpy as np
import time
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from core.flow_tracker import PacketMetadata


CLASS_NAMES = [
    "BENIGN_WEB",
    "BENIGN_STREAM",
    "SCAN_RECON",
    "DATA_EXFIL",
    "C2_BEACON"
]

CLASS_TO_ID = {name: i for i, name in enumerate(CLASS_NAMES)}
ID_TO_CLASS = {i: name for i, name in enumerate(CLASS_NAMES)}


class TrafficGenerator:
    """
    Generates synthetic packet flows simulating realistic network behavior.
    Allows testing early-flow observation windows (e.g. N = 5, 10, 20, 50 packets).
    """

    def __init__(self, random_seed: int = 42):
        np.random.seed(random_seed)

    def generate_flow(
        self,
        class_name: str,
        num_packets: int = 50,
        padding_bytes: int = 0,
        jitter_ms: float = 0.0,
        start_time: Optional[float] = None
    ) -> List[PacketMetadata]:
        """
        Generates an ordered list of PacketMetadata objects matching the specified behavioral profile.
        Optional padding_bytes and jitter_ms allow simulating adversarial traffic-shaping evasion.
        """
        now = start_time if start_time is not None else time.time()
        packets: List[PacketMetadata] = []
        curr_time = now

        if class_name == "BENIGN_WEB":
            # Human browsing: initial TCP/TLS handshake -> small request -> burst of response packets -> human think pause
            for i in range(num_packets):
                if i == 0:
                    size = 64
                    direction = 1  # SYN
                    iat = 0.0
                elif i == 1:
                    size = 64
                    direction = -1  # SYN-ACK
                    iat = np.random.uniform(0.015, 0.040)
                elif i == 2:
                    size = 517  # TLS Client Hello
                    direction = 1
                    iat = np.random.uniform(0.005, 0.020)
                elif i < 15:
                    # Inbound web resources (images, JS, HTML)
                    size = int(np.random.choice([64, 512, 1420], p=[0.2, 0.2, 0.6]))
                    direction = -1 if np.random.rand() > 0.15 else 1
                    iat = np.random.exponential(scale=0.012)
                else:
                    # Human reading or idle pause
                    size = int(np.random.choice([64, 1420], p=[0.4, 0.6]))
                    direction = -1 if np.random.rand() > 0.25 else 1
                    iat = np.random.uniform(0.150, 0.800)

                # Apply adversarial perturbations if enabled
                size = min(size + padding_bytes, 1500)
                iat = max(iat + (jitter_ms / 1000.0), 0.0001)

                curr_time += iat
                packets.append(PacketMetadata(
                    timestamp=curr_time,
                    size=size,
                    direction=direction,
                    tcp_window=int(np.random.choice([32768, 65535, 131072])),
                    tcp_flags={"SYN": i == 0, "ACK": True, "FIN": False, "RST": False, "PSH": size > 500, "URG": False},
                    header_length=40
                ))

        elif class_name == "BENIGN_STREAM":
            # Video streaming: steady large downlink packets with uniform intervals
            for i in range(num_packets):
                direction = -1 if i % 6 != 0 else 1
                size = 1420 if direction == -1 else 64
                iat = np.random.normal(loc=0.008, scale=0.002)
                iat = max(iat, 0.001)

                size = min(size + padding_bytes, 1500)
                iat = max(iat + (jitter_ms / 1000.0), 0.0001)

                curr_time += iat
                packets.append(PacketMetadata(
                    timestamp=curr_time,
                    size=size,
                    direction=direction,
                    tcp_window=65535,
                    tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False},
                    header_length=40
                ))

        elif class_name == "SCAN_RECON":
            # Port scanning: rapid trains of small SYN packets, minimal response
            for i in range(num_packets):
                direction = 1 if i % 10 != 0 else -1
                size = int(np.random.choice([44, 60, 74]))
                iat = np.random.exponential(scale=0.003)  # Rapid 3ms intervals

                size = min(size + padding_bytes, 1500)
                iat = max(iat + (jitter_ms / 1000.0), 0.0001)

                curr_time += iat
                packets.append(PacketMetadata(
                    timestamp=curr_time,
                    size=size,
                    direction=direction,
                    tcp_window=int(np.random.choice([1024, 2048, 4096])),
                    tcp_flags={"SYN": True, "ACK": direction == -1, "FIN": False, "RST": direction == -1, "PSH": False, "URG": False},
                    header_length=40
                ))

        elif class_name == "DATA_EXFIL":
            # Data theft: relentless upload of full MTU packets with minimal pause
            for i in range(num_packets):
                direction = 1 if i % 12 != 0 else -1  # 90%+ upload
                size = 1440 if direction == 1 else 64
                iat = np.random.normal(loc=0.0012, scale=0.0003)  # ~1.2ms machine speed
                iat = max(iat, 0.0002)

                size = min(size + padding_bytes, 1500)
                iat = max(iat + (jitter_ms / 1000.0), 0.0001)

                curr_time += iat
                packets.append(PacketMetadata(
                    timestamp=curr_time,
                    size=size,
                    direction=direction,
                    tcp_window=32768,
                    tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": direction == 1, "URG": False},
                    header_length=40
                ))

        elif class_name == "C2_BEACON":
            # Botnet heartbeat: clock-like fixed intervals, small fixed payload
            beacon_interval = 0.050  # 50ms pulse
            for i in range(num_packets):
                direction = 1 if i % 2 == 0 else -1
                size = 128 if direction == 1 else 96
                # Very low jitter in raw C2 beacons
                iat = np.random.normal(loc=beacon_interval, scale=0.001)
                iat = max(iat, 0.005)

                size = min(size + padding_bytes, 1500)
                iat = max(iat + (jitter_ms / 1000.0), 0.0001)

                curr_time += iat
                packets.append(PacketMetadata(
                    timestamp=curr_time,
                    size=size,
                    direction=direction,
                    tcp_window=16384,
                    tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True, "URG": False},
                    header_length=40
                ))

        return packets

    def generate_dataset(
        self,
        samples_per_class: int = 1000,
        observation_window: int = 20,
        padding_bytes: int = 0,
        jitter_ms: float = 0.0
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Generates full labeled dataset.
        Returns:
            X_tabular: np.ndarray of shape (N_samples, 13)
            X_sequence: np.ndarray of shape (N_samples, observation_window, 4)
            y: np.ndarray of shape (N_samples,)
        """
        from core.feature_extractor import FeatureExtractor
        extractor = FeatureExtractor(observation_window=observation_window)

        tabular_list = []
        sequence_list = []
        labels_list = []

        for class_idx, class_name in enumerate(CLASS_NAMES):
            for _ in range(samples_per_class):
                # Randomize flow duration slightly
                packets = self.generate_flow(
                    class_name=class_name,
                    num_packets=observation_window,
                    padding_bytes=padding_bytes,
                    jitter_ms=jitter_ms
                )
                vec = extractor.extract_vector(packets)
                seq = extractor.extract_sequence(packets, pad_length=observation_window)

                tabular_list.append(vec)
                sequence_list.append(seq)
                labels_list.append(class_idx)

        X_tab = np.array(tabular_list, dtype=np.float32)
        X_seq = np.array(sequence_list, dtype=np.float32)
        y = np.array(labels_list, dtype=np.int64)

        # Shuffle deterministically
        indices = np.arange(len(y))
        np.random.shuffle(indices)

        return X_tab[indices], X_seq[indices], y[indices]
