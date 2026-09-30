# Product Requirements Document (PRD)
## Project: EncryptedFlow AI
### Subtitle: Payload-Agnostic Threat Detection & Early-Flow Classification on Encrypted Traffic (TLS 1.3 / HTTPS)

---

## 1. Document Control
* **Author**: Akash Kumar (VIT Pune)
* **Version**: 1.0.0
* **Status**: Approved for Engineering
* **Target Domain**: Network Security, Deep Learning, High-Throughput Telemetry

---

## 2. Problem Statement & Motivation

### 2.1 The Operational Blindspot
Modern enterprise and web communications have achieved near-universal encryption: over 95% of all web and application traffic is encrypted using TLS 1.2, TLS 1.3, or QUIC. 

While this shift has drastically enhanced user privacy, it has crippled traditional enterprise security infrastructure:
1. **Death of Deep Packet Inspection (DPI)**: Traditional firewalls, Intrusion Detection Systems (IDS), and Unified Threat Management (UTM) appliances rely on matching regex signatures against unencrypted packet payloads. In TLS 1.3, application payloads, server certificates, and session tickets are fully encrypted.
2. **The Infeasibility of SSL Bumping (MITM Decryption)**: Man-in-the-Middle decryption proxies violate user privacy regulations (GDPR, HIPAA, DPDP Act), introduce severe CPU bottlenecks, increase packet round-trip latency, and break modern TLS features such as Encrypted Client Hello (ECH) and certificate pinning.
3. **Malware Weaponization of Encryption**: Advanced Persistent Threats (APTs), botnets, ransomware operators, and malicious insiders exploit this blindspot by routing Command-and-Control (C2) heartbeats, port-scanning reconnaissance, and data exfiltration through legitimate HTTPS tunnels.

### 2.2 The Engineering Challenge
The fundamental engineering dilemma is:
> *Can an intrusion detection engine reliably identify malicious behavior within an encrypted connection without decrypting the application payload, using solely the observable physical dynamics of early packets?*

---

## 3. Product Goals & Non-Goals

### 3.1 Primary Goals
* **G1: Payload Agnosticism**: Inspect zero bytes of application-layer payload. Classification must rely purely on link/transport-layer metadata (sizes, timing, direction, TCP window, packet rates).
* **G2: Early-Stage Horizon Classification**: Deliver an initial threat determination within the first $N$ packets ($N \in [5, 50]$) before full transfer completes.
* **G3: Multi-Model Empirical Evaluation**: Implement and benchmark 5 model architectures:
  1. Random Forest (Baseline)
  2. XGBoost (Gradient Boosted Trees Baseline)
  3. 1D-CNN (Temporal Local Patterns)
  4. Bidirectional LSTM (Sequential Dependency Modeling)
  5. Hybrid CNN + BiLSTM (Spatial-Temporal Representation)
* **G4: Explainable Threat Attribution**: Accompany every prediction with human-auditable physical network evidence (e.g., burstiness, inter-arrival variance, upload/download bias).
* **G5: Real-Time Telemetry & Operations Console**: Stream live traffic states, waveforms, latency percentiles ($p50, p95, p99$), and alert feeds to an interactive Security Operations Center (SOC) dashboard.
* **G6: Adversarial Robustness Testing**: Measure detection resilience against deliberate traffic-shaping evasion (inter-packet delay jitter and packet padding).

### 3.2 Non-Goals (Out of Scope for v1.0)
* **NG1: Payload Decryption**: The system will not perform private key ingestion or TLS proxying.
* **NG2: Active Automated Packet Dropping (Inline IPS)**: v1.0 functions as a passive detection, telemetry, and alerting mesh; active firewall kernel rule injection (eBPF/iptables drop) is scheduled for v2.0.
* **NG3: Heavy Foundation LLMs**: The system deliberately excludes multi-billion parameter LLMs at the network boundary to ensure CPU-friendly sub-millisecond throughput.

---

## 4. User Personas & Target Stakeholders

| Persona | Role | Primary Need |
| :--- | :--- | :--- |
| **SOC Security Analyst** | Tier-1/Tier-2 Enterprise Security | Immediate, explainable alerts without false-alarm fatigue; clear physical evidence. |
| **Network Infrastructure Engineer** | Data Center / Switch Management | Predictable, lightweight CPU resource consumption without latency spikes or packet drops. |
| **Technical Interviewer / Evaluator** | Tier-1 Recruiter (Barclays, Cisco, Nvidia) | Scientifically defensible architecture, empirical benchmarks, and clear CS fundamentals. |

---

## 5. Functional Requirements (FR)

### 5.1 Flow Ingestion & State Tracking
* **FR-1.1**: The system shall assemble incoming packets into bidirectional 5-tuple flows: `(Source IP, Source Port, Destination IP, Destination Port, Protocol)`.
* **FR-1.2**: Standardize canonical flow identification so client-to-server and server-to-client packets map to the identical session.
* **FR-1.3**: Support configurable packet observation windows ($N = 5, 10, 20, 50$).
* **FR-1.4**: Automatically purge expired or TCP-terminated (FIN/RST) flows after an idle timeout ($\tau = 30\text{s}$).

### 5.2 Feature Extraction (13 Payload-Agnostic Dimensions)
* **FR-2.1**: The system shall extract 13 statistical and sequence features exclusively from transport headers:
  1. Mean Packet Size
  2. Standard Deviation of Packet Size
  3. Maximum Packet Size
  4. Minimum Packet Size
  5. Mean Inter-Arrival Time (IAT)
  6. Standard Deviation of IAT
  7. Maximum IAT
  8. Total Flow Duration (Observation Window)
  9. Forward-to-Backward Packet Ratio
  10. Forward-to-Backward Byte Ratio
  11. Instantaneous Packet Rate (pkts/sec)
  12. Instantaneous Byte Rate (bytes/sec)
  13. Mean TCP Advertised Window Size

### 5.3 Classification & Machine Learning Engine
* **FR-3.1**: Support multi-class threat taxonomy:
  * **Class 0**: `BENIGN_HTTPS` (Standard web browsing, REST API, video stream)
  * **Class 1**: `SCANNING` (Stealth TCP SYN / Port Scan reconnaissance)
  * **Class 2**: `DATA_EXFILTRATION` (Asymmetric high-volume upstream tunnel)
  * **Class 3**: `DDOS_BURST` (High-frequency volumetric burst)
  * **Class 4**: `C2_BEACONING` (Periodic low-jitter botnet heartbeat)
* **FR-3.2**: Output prediction class, confidence probability ($[0.0, 1.0]$), and confidence status.

### 5.4 Explainability Layer (Evidence Generator)
* **FR-4.1**: For any flow categorized as suspicious/threat, the engine shall compute feature attribution against baseline benign distributions.
* **FR-4.2**: Generate plain-language physical evidence bullets (e.g., *"Upstream byte ratio 12.4x higher than benign baseline; IAT variance < 0.2ms indicating machine-generated burst"*).

### 5.5 Real-Time Server & WebSocket Streaming
* **FR-5.1**: Provide a high-concurrency FastAPI server exposing REST configuration and streaming WebSockets.
* **FR-5.2**: Broadcast real-time flow events, waveform telemetry, threat alerts, and system health.

### 5.6 Security Operations Center (SOC) UI
* **FR-6.1**: Real-time traffic oscilloscope / packet waveform monitor.
* **FR-6.2**: Live Threat Feed displaying timestamp, 5-tuple, classification, confidence, and physical evidence.
* **FR-6.3**: Interactive Simulation Panel allowing the user to trigger Benign, Exfiltration, Scanning, or C2 traffic with one click.
* **FR-6.4**: Real-time Latency Meter displaying measured $p50, p95, p99$ timings.

---

## 6. Non-Functional Requirements (NFR)

* **NFR-1 (Inference Latency)**: Model inference on an observation window must complete in under $2.0\text{ms}$ on commodity x86_64 CPU hardware.
* **NFR-2 (Memory Footprint)**: Total model parameter footprint must remain under $150,000$ parameters ($< 2\text{MB}$ storage).
* **NFR-3 (Zero Data Retention)**: Raw packet byte payloads shall never be logged, cached, or written to disk.
* **NFR-4 (Extensibility)**: Modular architecture allowing new classifiers or feature definitions to be swapped without modifying ingestion logic.

---

## 7. Acceptance Criteria

| ID | Criterion | Verification Method |
| :--- | :--- | :--- |
| **AC-1** | Zero payload inspection verified across all code modules. | Static code analysis verifying only header metadata is accessed. |
| **AC-2** | Multi-model benchmark suite generates full comparative metrics. | Execution of `benchmark/runner.py` producing comparative table. |
| **AC-3** | Early-packet horizon evaluated across 5, 10, 20, 50 packets. | Execution of `benchmark/window_evaluator.py`. |
| **AC-4** | Evasion test measures degradation under padding and jitter. | Execution of `benchmark/evasion_simulator.py`. |
| **AC-5** | Real-time dashboard renders live packet waveforms and alerts. | Manual verification in browser with simulated traffic injection. |
