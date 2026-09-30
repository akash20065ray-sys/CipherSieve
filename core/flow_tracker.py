"""
EncryptedFlow AI - Core Flow Tracker
Maintains bidirectional 5-tuple network flow state across incoming packets.
Extracts early-flow packet sequences for payload-agnostic classification.
"""

import time
from typing import Dict, Tuple, List, Optional
from dataclasses import dataclass, field


@dataclass
class PacketMetadata:
    """Represents observable transport/link-layer metadata of a single packet."""
    timestamp: float
    size: int
    direction: int  # +1 for client-to-server (forward), -1 for server-to-client (backward)
    tcp_window: int
    tcp_flags: Dict[str, bool]
    header_length: int


@dataclass
class FlowState:
    """Tracks state and packet history for a bidirectional 5-tuple connection."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packets: List[PacketMetadata] = field(default_factory=list)
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    is_closed: bool = False

    def add_packet(self, meta: PacketMetadata):
        """Appends packet metadata and updates directional counters."""
        self.packets.append(meta)
        self.last_seen = meta.timestamp

        if meta.direction == 1:
            self.total_fwd_packets += 1
            self.total_fwd_bytes += meta.size
        else:
            self.total_bwd_packets += 1
            self.total_bwd_bytes += meta.size

        # Check for TCP termination flags (FIN or RST)
        if meta.tcp_flags.get("FIN", False) or meta.tcp_flags.get("RST", False):
            self.is_closed = True


class FlowTracker:
    """
    Manages active network flows, assigning packets to bidirectional 5-tuples.
    Allows extracting the first N packets of a connection for early threat detection.
    """
    def __init__(self, idle_timeout: float = 30.0, max_packets_per_flow: int = 50, observation_window: Optional[int] = None):
        self.idle_timeout = idle_timeout
        self.max_packets_per_flow = observation_window if observation_window is not None else max_packets_per_flow
        self.active_flows: Dict[str, FlowState] = {}

    @staticmethod
    def get_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> Tuple[str, int]:
        """
        Generates a canonical bidirectional flow ID.
        Returns:
            canonical_key: str
            direction: +1 if client-to-server, -1 if reverse
        """
        forward_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
        backward_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}:{protocol}"

        # Standard convention: lowest IP:port is considered forward channel origin
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return forward_key, 1
        else:
            return backward_key, -1

    def process_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        size: int,
        tcp_window: int = 65535,
        tcp_flags: Optional[Dict[str, bool]] = None,
        header_length: int = 40,
        timestamp: Optional[float] = None
    ) -> Tuple[str, FlowState, bool]:
        """
        Ingests a packet, associates it with a flow, and returns:
            (flow_id, flow_state, is_new_flow)
        """
        now = timestamp if timestamp is not None else time.time()
        canonical_key, direction = self.get_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)

        flags = tcp_flags if tcp_flags is not None else {
            "SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False
        }

        meta = PacketMetadata(
            timestamp=now,
            size=size,
            direction=direction,
            tcp_window=tcp_window,
            tcp_flags=flags,
            header_length=header_length
        )

        is_new = False
        if canonical_key not in self.active_flows:
            self.active_flows[canonical_key] = FlowState(
                flow_id=canonical_key,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                start_time=now,
                last_seen=now
            )
            is_new = True

        flow = self.active_flows[canonical_key]
        flow.add_packet(meta)

        return canonical_key, flow, is_new

    def get_early_packets(self, flow_id: str, n: int = 20) -> List[PacketMetadata]:
        """Returns the first n packets observed for the given flow ID."""
        flow = self.active_flows.get(flow_id)
        if not flow:
            return []
        return flow.packets[:n]

    def purge_idle_flows(self, current_time: Optional[float] = None) -> int:
        """Cleans up inactive or closed flows exceeding the idle timeout."""
        now = current_time if current_time is not None else time.time()
        expired_keys = [
            k for k, v in self.active_flows.items()
            if (now - v.last_seen > self.idle_timeout) or v.is_closed
        ]
        for k in expired_keys:
            del self.active_flows[k]
        return len(expired_keys)
