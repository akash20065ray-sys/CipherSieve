"""
CipherSieve - Real-World PCAP Dataset Loader & Replayer
Handles parsing, flow aggregation, and pacing replay of standard .pcap and .pcapng files.
Works with Scapy and includes a zero-dependency binary PCAP reader fallback.
Includes realistic sample PCAP generator for testing and demonstration.
"""

import os
import sys
import time
import struct

# Project root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import Dict, List, Tuple, Generator, Optional, Any, Callable
from dataclasses import dataclass

from core.flow_tracker import FlowTracker, PacketMetadata, FlowState

# Try importing scapy layers
try:
    from scapy.all import (
        PcapReader, wrpcap, Ether, IP, TCP, UDP, Raw
    )
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


@dataclass
class RawPacketInfo:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    length: int
    tcp_window: int
    tcp_flags: Dict[str, bool]
    header_length: int


class PCAPLoader:
    """
    Parses and replays standard .pcap / .pcapng network capture files.
    Aggregates packets into 5-tuple flows using FlowTracker.
    """
    def __init__(self, observation_window: int = 20):
        self.observation_window = observation_window

    def parse_pcap_scapy(self, filepath: str) -> Generator[RawPacketInfo, None, None]:
        """Streams packets from PCAP using Scapy PcapReader."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        with PcapReader(filepath) as reader:
            for pkt in reader:
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                proto = "OTHER"
                sport = 0
                dport = 0
                win = 65535
                flags = {"SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
                hdr_len = 40

                if pkt.haslayer(TCP):
                    proto = "TCP"
                    tcp_layer = pkt[TCP]
                    sport = int(tcp_layer.sport)
                    dport = int(tcp_layer.dport)
                    win = int(tcp_layer.window)
                    # Scapy flags representation
                    f_str = str(tcp_layer.flags)
                    flags = {
                        "SYN": "S" in f_str,
                        "ACK": "A" in f_str,
                        "FIN": "F" in f_str,
                        "RST": "R" in f_str,
                        "PSH": "P" in f_str,
                        "URG": "U" in f_str
                    }
                    hdr_len = (ip_layer.ihl * 4) + (tcp_layer.dataofs * 4)
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    udp_layer = pkt[UDP]
                    sport = int(udp_layer.sport)
                    dport = int(udp_layer.dport)
                    hdr_len = (ip_layer.ihl * 4) + 8

                pkt_len = len(pkt)
                ts = float(pkt.time)

                yield RawPacketInfo(
                    timestamp=ts,
                    src_ip=str(ip_layer.src),
                    src_port=sport,
                    dst_ip=str(ip_layer.dst),
                    dst_port=dport,
                    protocol=proto,
                    length=pkt_len,
                    tcp_window=win,
                    tcp_flags=flags,
                    header_length=hdr_len
                )

    def parse_pcap_binary_fallback(self, filepath: str) -> Generator[RawPacketInfo, None, None]:
        """
        Pure-Python fallback PCAP reader for standard libpcap format (RFC 0xa1b2c3d4).
        Decodes Ethernet (14B) + IPv4 (20B) + TCP (20B) without Scapy dependency.
        """
        with open(filepath, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            magic, v_major, v_minor, tz, sigfigs, snaplen, network = struct.unpack("=IHHiIII", global_header)
            is_le = (magic == 0xa1b2c3d4)

            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII" if is_le else ">IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                # Parse Ethernet frame (14 bytes)
                if len(pkt_data) < 34:  # 14 Ethernet + 20 IP minimum
                    continue

                eth_type = struct.unpack(">H", pkt_data[12:14])[0]
                if eth_type != 0x0800:  # IPv4 only
                    continue

                ip_data = pkt_data[14:]
                ihl = (ip_data[0] & 0x0f) * 4
                proto_num = ip_data[9]
                src_ip = ".".join(str(b) for b in ip_data[12:16])
                dst_ip = ".".join(str(b) for b in ip_data[16:20])

                if proto_num == 6:  # TCP
                    tcp_data = ip_data[ihl:]
                    if len(tcp_data) < 20:
                        continue
                    sport, dport, seq, ack, offset_reserved, flags_byte, win = struct.unpack(">HHIIBBH", tcp_data[:18])
                    data_offset = (offset_reserved >> 4) * 4
                    flags = {
                        "SYN": bool(flags_byte & 0x02),
                        "ACK": bool(flags_byte & 0x10),
                        "FIN": bool(flags_byte & 0x01),
                        "RST": bool(flags_byte & 0x04),
                        "PSH": bool(flags_byte & 0x08),
                        "URG": bool(flags_byte & 0x20),
                    }
                    ts = ts_sec + (ts_usec / 1_000_000.0)
                    yield RawPacketInfo(
                        timestamp=ts,
                        src_ip=src_ip,
                        src_port=sport,
                        dst_ip=dst_ip,
                        dst_port=dport,
                        protocol="TCP",
                        length=orig_len,
                        tcp_window=win,
                        tcp_flags=flags,
                        header_length=14 + ihl + data_offset
                    )

    def extract_flows(self, filepath: str) -> Dict[str, FlowState]:
        """
        Parses PCAP file and aggregates packets into bidirectional 5-tuple flows.
        """
        tracker = FlowTracker(observation_window=self.observation_window)

        parser = self.parse_pcap_scapy if SCAPY_AVAILABLE else self.parse_pcap_binary_fallback

        for pkt in parser(filepath):
            tracker.process_packet(
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                size=pkt.length,
                tcp_window=pkt.tcp_window,
                tcp_flags=pkt.tcp_flags,
                header_length=pkt.header_length,
                timestamp=pkt.timestamp
            )

        return tracker.active_flows

    def replay_pcap(
        self,
        filepath: str,
        speed_multiplier: float = 1.0,
        packet_callback: Optional[Callable[[RawPacketInfo, FlowState, bool], None]] = None,
        flow_complete_callback: Optional[Callable[[FlowState], None]] = None,
        max_packets: int = 1000
    ) -> int:
        """
        Replays PCAP with realistic inter-arrival delays scaled by speed_multiplier.
        speed_multiplier: 1.0 = real-time, 5.0 = 5x faster, 0 = no sleep (burst mode)
        """
        tracker = FlowTracker(observation_window=self.observation_window)
        parser = self.parse_pcap_scapy if SCAPY_AVAILABLE else self.parse_pcap_binary_fallback

        prev_orig_ts = None
        count = 0
        reported_flows = set()

        for pkt in parser(filepath):
            if count >= max_packets:
                break

            if speed_multiplier > 0 and prev_orig_ts is not None:
                delta = pkt.timestamp - prev_orig_ts
                if 0 < delta < 2.0:
                    time.sleep(delta / speed_multiplier)

            prev_orig_ts = pkt.timestamp

            flow_id, flow_state, is_new = tracker.process_packet(
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                size=pkt.length,
                tcp_window=pkt.tcp_window,
                tcp_flags=pkt.tcp_flags,
                header_length=pkt.header_length,
                timestamp=time.time()
            )

            count += 1
            if packet_callback:
                packet_callback(pkt, flow_state, is_new)

            # If flow has reached observation window, notify completion
            if len(flow_state.packets) >= self.observation_window and flow_id not in reported_flows:
                reported_flows.add(flow_id)
                if flow_complete_callback:
                    flow_complete_callback(flow_state)

        # Flush any remaining flows with at least 5 packets
        if flow_complete_callback:
            for fid, fstate in tracker.active_flows.items():
                if fid not in reported_flows and len(fstate.packets) >= 5:
                    reported_flows.add(fid)
                    flow_complete_callback(fstate)

        return count


def generate_sample_pcaps(output_dir: str):
    """
    Generates realistic, binary-valid .pcap files representing the 4 key scenarios:
    1. benign_web_tls.pcap
    2. c2_beacon_heartbeat.pcap
    3. data_exfiltration.pcap
    4. stealth_port_scan.pcap
    """
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is required to generate sample PCAP files.")
        return

    os.makedirs(output_dir, exist_ok=True)
    import numpy as np

    scenarios = [
        ("benign_web_tls.pcap", "BENIGN_WEB", 3, "192.168.1.105", "104.16.132.229", 443),
        ("c2_beacon_heartbeat.pcap", "C2_BEACON", 4, "192.168.1.88", "185.220.101.5", 8443),
        ("data_exfiltration.pcap", "DATA_EXFIL", 3, "192.168.1.150", "45.33.32.156", 443),
        ("stealth_port_scan.pcap", "SCAN_RECON", 5, "192.168.1.200", "192.168.1.1", 80),
    ]

    for filename, attack_type, num_flows, src_base, dst_base, target_port in scenarios:
        out_path = os.path.join(output_dir, filename)
        all_pkts = []
        base_time = 1727740800.0  # Stable reference epoch

        for f_idx in range(num_flows):
            client_port = 49152 + f_idx * 100
            t = base_time + (f_idx * 1.5)

            # Three-way TCP Handshake (SYN, SYN-ACK, ACK)
            syn = Ether()/IP(src=src_base, dst=dst_base)/TCP(sport=client_port, dport=target_port, flags="S", seq=1000, window=64240)
            syn.time = t
            all_pkts.append(syn)
            t += 0.015

            synack = Ether()/IP(src=dst_base, dst=src_base)/TCP(sport=target_port, dport=client_port, flags="SA", seq=5000, ack=1001, window=65535)
            synack.time = t
            all_pkts.append(synack)
            t += 0.012

            ack = Ether()/IP(src=src_base, dst=dst_base)/TCP(sport=client_port, dport=target_port, flags="A", seq=1001, ack=5001, window=64240)
            ack.time = t
            all_pkts.append(ack)
            t += 0.005

            # Flow-specific dynamic payload distribution
            if attack_type == "BENIGN_WEB":
                # TLS Client Hello (~512 bytes)
                req = Ether()/IP(src=src_base, dst=dst_base)/TCP(sport=client_port, dport=target_port, flags="PA", seq=1001, ack=5001, window=64240)/Raw(load=b"\x16\x03\x01" + b"\x00" * 509)
                req.time = t
                all_pkts.append(req)
                t += 0.035

                # Server Response chunks (Download heavy)
                for c in range(12):
                    resp = Ether()/IP(src=dst_base, dst=src_base)/TCP(sport=target_port, dport=client_port, flags="PA", seq=5001 + c*1420, ack=1513, window=65535)/Raw(load=b"\x17\x03\x03" + b"\xaa" * 1417)
                    resp.time = t
                    all_pkts.append(resp)
                    t += np.random.uniform(0.001, 0.008)

            elif attack_type == "C2_BEACON":
                # Periodic fixed small heartbeats
                for b in range(14):
                    b_req = Ether()/IP(src=src_base, dst=dst_base)/TCP(sport=client_port, dport=target_port, flags="PA", seq=1001 + b*96, ack=5001, window=16384)/Raw(load=b"\x17\x03\x03" + b"\xbb" * 93)
                    b_req.time = t
                    all_pkts.append(b_req)
                    t += 0.050 + np.random.uniform(-0.001, 0.001)

                    b_resp = Ether()/IP(src=dst_base, dst=src_base)/TCP(sport=target_port, dport=client_port, flags="A", seq=5001, ack=1097 + b*96, window=16384)
                    b_resp.time = t + 0.002
                    all_pkts.append(b_resp)

            elif attack_type == "DATA_EXFIL":
                # Upload heavy - continuous 1440B MTU packets sent rapidly
                for e in range(16):
                    exfil = Ether()/IP(src=src_base, dst=dst_base)/TCP(sport=client_port, dport=target_port, flags="PA", seq=1001 + e*1440, ack=5001, window=32768)/Raw(load=b"\x17\x03\x03" + b"\xee" * 1437)
                    exfil.time = t
                    all_pkts.append(exfil)
                    t += np.random.uniform(0.0005, 0.0015)

            elif attack_type == "SCAN_RECON":
                # Multiple destination ports with tiny SYN probes
                for p_target in [21, 22, 23, 25, 80, 443, 3306, 8080]:
                    probe = Ether()/IP(src=src_base, dst=dst_base)/TCP(sport=client_port + p_target, dport=p_target, flags="S", seq=2000, window=1024)
                    probe.time = t
                    all_pkts.append(probe)
                    t += np.random.uniform(0.002, 0.005)

        # Sort all packets strictly by timestamp
        all_pkts.sort(key=lambda p: float(p.time))
        wrpcap(out_path, all_pkts)
        print(f"[+] Generated sample PCAP: {out_path} ({len(all_pkts)} packets)")


if __name__ == "__main__":
    samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "samples"))
    generate_sample_pcaps(samples_dir)
