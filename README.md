# CipherSieve

> **Payload-Agnostic Early-Flow Threat Detection & Behavioral Classification in Encrypted (TLS 1.3 / HTTPS) Traffic**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-ee4c2c.svg)](https://pytorch.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

Over 95% of enterprise and consumer web traffic is encrypted with TLS 1.3 and HTTPS. While essential for user privacy, this has rendered traditional **Deep Packet Inspection (DPI)** firewalls and intrusion detection systems completely blind. Man-in-the-Middle (MITM) decryption appliances are computationally prohibitive, violate user privacy regulations (GDPR, DPDP), and break modern TLS features such as Encrypted Client Hello (ECH).

**CipherSieve** resolves this privacy-versus-security dilemma:
Instead of inspecting encrypted application payloads, CipherSieve treats early packet flows like physical temporal signals—extracting **13 transport-layer metadata features** (sizes, inter-arrival times, directional byte ratios, and TCP window dynamics) from the first $N$ packets of a connection ($N \in [5, 50]$) to classify cyberattacks in real-time with sub-millisecond median latency on standard CPU hardware.

---

## System Architecture

```
                    RAW NETWORK STREAM (TLS 1.3 / HTTPS)
                                      │
                                      ▼
                       ┌─────────────────────────────┐
                       │  Packet Ingestion & Sniffer │ (PCAP / Live Sockets)
                       └──────────────┬──────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────┐
                       │    Bidirectional Flow Hub   │ (5-Tuple Session Grouping)
                       └──────────────┬──────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────┐
                       │  13-Feature Metadata Engine │ (Zero Payload Inspection)
                       └──────────────┬──────────────┘
                                      │
                           First N Packets Window (5, 10, 20, 50)
                                      │
                                      ▼
                 ┌────────────────────────────────────────┐
                 │       Multi-Model Evaluation Core      │
                 │ ────────────────────────────────────── │
                 │ • Classical: Random Forest & GBDT      │
                 │ • Neural: 1D-CNN, BiLSTM, Hybrid       │
                 └────────────────────┬───────────────────┘
                                      │
                                      ▼
                 ┌────────────────────────────────────────┐
                 │    Explainability & Evidence Engine    │
                 │ (Extracts contributing network tokens) │
                 └────────────────────┬───────────────────┘
                                      │
                                      ▼
                 ┌────────────────────────────────────────┐
                 │   Real-Time FastAPI WebSocket Server   │
                 └────────────────────┬───────────────────┘
                                      │
                                      ▼
                 ┌────────────────────────────────────────┐
                 │  Cyber Defense Operations UI (SOC)     │
                 │  - Live Packet Rhythms (Waveform)      │
                 │  - 3-Stage Forensic Flow Inspector    │
                 │  - Dual-Mode Simulator & Latency Meter │
                 └────────────────────────────────────────┘
```

---

## Core Research Questions (RQs)

1. **RQ1 (Detection Feasibility)**: Can payload-agnostic metadata distinguish benign encrypted sessions from malicious flows without payload inspection?
2. **RQ2 (Observation Horizon)**: What is the relationship between classification accuracy and early-flow depth ($N = 5, 10, 20, 50$ packets)?
3. **RQ3 (Model Comparison)**: Do deep neural sequence architectures (1D-CNN, BiLSTM, Hybrid) outperform classical tree ensembles (Random Forest, GBDT) on temporal flow dynamics?
4. **RQ4 (Adversarial Robustness)**: How resilient is detection against deliberate traffic shaping (random padding $0 - 200\text{B}$ and jitter $10 - 100\text{ms}$)?
5. **RQ5 (Granular Latency Profiling)**: What are the measured $p50, p95,$ and $p99$ latencies across capture, extraction, inference, and alert stages?

---

## Evaluated Traffic Taxonomy

* **`BENIGN_WEB`**: Human browsing with bursty arrivals and human think-time pauses ($0.2 - 2.0\text{s}$).
* **`BENIGN_STREAM`**: Sustained downstream streaming with uniform MTU packet intervals.
* **`DATA_EXFILTRATION`**: High-volume asymmetric upload streams (forward byte ratio $> 10\times$).
* **`SCAN_RECON`**: Rapid machine-gun trains of small probe packets ($40 - 74\text{B}$) with near-zero IAT.
* **`C2_BEACON`**: Periodic, low-jitter deterministic botnet heartbeats.

---

## 3-Stage Forensic Flow Inspector

When an alert is flagged in the live SOC console, CipherSieve visualizes the complete end-to-end data transformation:

```
RAW OBSERVATION (Early Packets)
  ├─ Pkt 01: 517 B  (Client -> Server)
  ├─ Pkt 02: 1440 B (Client -> Server)
  └─ Pkt 03: 1440 B (Client -> Server)
        │
        ▼
FEATURE EXTRACTION (13 Observable Dimensions)
  ├─ Mean Size: 1380 B
  ├─ Inter-Arrival Time: 1.10 ms
  └─ Upstream/Downstream Byte Ratio: 14.8x (Abnormal Upload Bias)
        │
        ▼
NEURAL INFERENCE & EXPLAINABILITY
  ├─ Predicted: DATA_EXFILTRATION (Confidence: 97.4%)
  └─ Physical Evidence: "Abnormal upstream upload bias + machine-gun 1.1ms intervals"
```

---

## Quickstart Guide

### 1. Installation
```bash
git clone https://github.com/akash20065ray-sys/CipherSieve.git
cd CipherSieve
pip install torch numpy scikit-learn fastapi uvicorn matplotlib
```

### 2. Train Models Manually
Train all 5 models (Random Forest, GBDT, 1D-CNN, BiLSTM, and Hybrid CNN+BiLSTM) on identical holdout splits:
```bash
python run.py train
```

### 3. Run Research Benchmark Suite
Evaluate observation horizons ($N=5, 10, 20, 50$), traffic-shaping evasion tests, and $p50/p95/p99$ latency profiles:
```bash
python run.py benchmark
```

### 4. Launch Live SOC Monitoring Dashboard
Launch the FastAPI WebSocket streaming backend and live dark-mode SOC dashboard:
```bash
python run.py serve
```
Open **`http://127.0.0.1:8000/index.html`** in your browser.

---

## License

MIT License. Developed by Akash Kumar (VIT Pune).
