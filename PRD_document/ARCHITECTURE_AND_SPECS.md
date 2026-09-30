# Technical Architecture & Engineering Specifications
## Project: EncryptedFlow AI
### Subtitle: System Architecture, Data Schemas, Neural Layer Specifications & Streaming Protocols

---

## 1. High-Level System Architecture

```
                  ┌──────────────────────────────────────────────────┐
                  │        RAW NETWORK / TRAFFIC GENERATOR           │
                  │   (PCAP / Live Sockets / Behavioral Streams)     │
                  └─────────────────────────┬────────────────────────┘
                                            │ Raw Packets (Headers only)
                                            ▼
                  ┌──────────────────────────────────────────────────┐
                  │             CORE FLOW TRACKER                    │
                  │   - Bidirectional 5-Tuple Canonical Hashing      │
                  │   - State Table with Automatic Expiration        │
                  │   - Early-Packet Window Buffer (N packets)       │
                  └─────────────────────────┬────────────────────────┘
                                            │ Observed Window W_N
                                            ▼
                  ┌──────────────────────────────────────────────────┐
                  │           METADATA FEATURE EXTRACTOR             │
                  │   - 13 Statistical Tabular Features              │
                  │   - N x 4 Temporal Sequence Matrix               │
                  └─────────────┬───────────────────────────┬────────┘
                                │                           │
                 Tabular Features [13]         Sequence Tensor [N x 4]
                                │                           │
                                ▼                           ▼
                  ┌──────────────────────┐    ┌──────────────────────┐
                  │   Tree Baselines     │    │    Neural Models     │
                  │   (RF / XGBoost)     │    │ (1D-CNN, BiLSTM, Hyb)│
                  └─────────────┬────────┘    └─────────────┬────────┘
                                │                           │
                                └─────────────┬─────────────┘
                                              │ Prediction & Logits
                                              ▼
                  ┌──────────────────────────────────────────────────┐
                  │           EXPLAINABILITY & EVIDENCE ENGINE       │
                  │   - Feature Attribution (Z-score vs Benign Base) │
                  │   - Physical Network Evidence Generation         │
                  └─────────────────────────┬────────────────────────┘
                                            │ Enriched Alert Event
                                            ▼
                  ┌──────────────────────────────────────────────────┐
                  │           FASTAPI WEBSOCKET STREAM SERVER        │
                  │   - Event Loop Broadcasting                      │
                  │   - Telemetry Queue & Latency Instrumentation    │
                  └─────────────────────────┬────────────────────────┘
                                            │ WebSocket JSON Stream
                                            ▼
                  ┌──────────────────────────────────────────────────┐
                  │       SECURITY OPERATIONS CENTER (SOC) UI        │
                  │   - Real-time Packet Rhythms Oscilloscope        │
                  │   - Live Threat Feed with Audit Evidence         │
                  │   - Interactive Attack & Evasion Simulator       │
                  │   - Real-time Latency Diagnostics Meter          │
                  └──────────────────────────────────────────────────┘
```

---

## 2. Directory Structure & Module Responsibilities

```
c:\PROJECT_PLAC
│
├── PRD_document/
│   ├── PRD.md                       # Product Requirements Document
│   ├── RESEARCH_AND_EXPERIMENTS.md  # Scientific methodology & 5 RQs
│   └── ARCHITECTURE_AND_SPECS.md    # Architecture & Data Schemas
│
├── core/
│   ├── flow_tracker.py              # Bidirectional 5-tuple state management
│   ├── feature_extractor.py         # 13-feature extractor & sequence builder
│   └── explainer.py                 # Evidence attribution generator
│
├── models/
│   ├── baselines.py                 # Random Forest & XGBoost / Decision Trees
│   ├── neural_models.py             # PyTorch 1D-CNN, BiLSTM, and Hybrid CNN+BiLSTM
│   └── trainer.py                   # Multi-model cross-validation & training loop
│
├── benchmark/
│   ├── synthetic_generator.py       # Ground-truth flow generation for all 5 classes
│   ├── window_evaluator.py          # RQ2: 5 vs 10 vs 20 vs 50 packet evaluation
│   ├── evasion_simulator.py         # RQ4: Adversarial traffic-shaping test
│   ├── latency_profiler.py          # RQ5: Granular p50/p95/p99 latency benchmarking
│   └── plot_results.py              # Publication-grade chart generation
│
├── server/
│   └── app.py                       # FastAPI backend + WebSocket streaming endpoint
│
├── dashboard/
│   ├── index.html                   # High-tech Cyber Defense SOC interface
│   ├── styles.css                   # Dark-mode glassmorphic styling & telemetry UI
│   └── app.js                       # Real-time WebSocket visualizer & controls
│
└── run.py                           # Master CLI entrypoint (train, benchmark, or serve)
```

---

## 3. Data Schemas & Contracts

### 3.1 PacketMetadata (Core Primitive)
```python
@dataclass
class PacketMetadata:
    timestamp: float        # Epoch timestamp with microsecond resolution
    size: int              # Wire length in bytes
    direction: int         # +1 (Client -> Server), -1 (Server -> Client)
    tcp_window: int        # Advertised TCP receive window size
    tcp_flags: Dict[str, bool] # {"SYN": bool, "ACK": bool, "FIN": bool, ...}
    header_length: int     # IP + TCP header length in bytes
```

### 3.2 WebSocket Telemetry Event (Server $\rightarrow$ Dashboard)
```json
{
  "type": "FLOW_EVENT",
  "data": {
    "flow_id": "192.168.1.105:54320->104.244.42.1:443:TCP",
    "timestamp": 1727718000.1245,
    "classification": "DATA_EXFILTRATION",
    "is_threat": true,
    "confidence": 0.964,
    "model_used": "Hybrid_CNN_BiLSTM",
    "packet_count": 20,
    "evidence": [
      "Upstream byte ratio 14.8x higher than normal baseline",
      "Sustained forward burst of 18 consecutive MTU packets",
      "Inter-arrival time variance < 0.3ms indicating automated egress"
    ],
    "metrics": {
      "mean_size": 1380.5,
      "mean_iat_ms": 1.2,
      "byte_rate_kbps": 920.4
    },
    "latency": {
      "extraction_ms": 0.12,
      "inference_ms": 0.61,
      "total_pipeline_ms": 0.73
    },
    "recent_packet_sizes": [64, 1420, 1420, 64, 1420, 1420, 1420, 1420]
  }
}
```

---

## 4. Deep Learning Model Architectures (PyTorch)

### 4.1 Hybrid CNN + BiLSTM (`HybridFlowClassifier`)
* **Input Shape**: `(Batch_Size, Sequence_Length, 4)`  
  * Each step: `[packet_size, inter_arrival_time, direction, tcp_window]`
* **Stage 1 (Local Feature Extraction - 1D-CNN)**:
  * Transpose to `(Batch_Size, 4, Sequence_Length)`
  * Conv1D: `in_channels=4, out_channels=32, kernel_size=3, padding=1`, followed by BatchNorm1d and ReLU
  * Conv1D: `in_channels=32, out_channels=64, kernel_size=3, padding=1`, followed by BatchNorm1d and ReLU
  * MaxPool1D: `kernel_size=2`
  * Dropout: `p=0.2`
* **Stage 2 (Sequential Dependency Modeling - BiLSTM)**:
  * Bidirectional LSTM: `input_size=64, hidden_size=64, num_layers=1, batch_first=True`
  * Outputs directional states: forward (64) + backward (64) = 128 dimensions.
* **Stage 3 (Classification Head)**:
  * Linear: `128 -> 64` + ReLU + Dropout(0.3)
  * Linear: `64 -> 5` (Logits for 5 traffic classes)
* **Total Parameters**: $\approx 68,500$ parameters ($< 300\text{KB}$ in memory).

---

## 5. Explainability Attribution Algorithm

To provide transparent physical evidence without black-box opacity:
1. Maintain running **rolling distributions** ($\mu_k, \sigma_k$) for each of the 13 features across confirmed benign traffic.
2. For any candidate flow flagged with threat probability $P(\text{Threat}) \ge 0.50$, compute the standardized Z-score for feature $k$:
   $$Z_k = \frac{x_k - \mu_k^{(\text{benign})}}{\sigma_k^{(\text{benign})} + \epsilon}$$
3. Rank features by magnitude $|Z_k|$.
4. Select the top-3 anomalous features exceeding threshold ($|Z_k| \ge 2.5$) and map them to physical security explanations.

---

## 6. Real-Time Streaming Server Specifications
* **Framework**: FastAPI (Asynchronous ASGI) with `uvicorn`.
* **Endpoints**:
  * `GET /api/health`: Health status and loaded model metadata.
  * `GET /api/benchmark/summary`: Returns precomputed evaluation matrices, F1 scores, and latency statistics.
  * `POST /api/simulate`: Triggers traffic injection (`BENIGN_WEB`, `SCANNING`, `DATA_EXFIL`, `C2_BEACON`).
  * `POST /api/evasion/toggle`: Toggles synthetic traffic-shaping (jitter delay + random padding).
  * `WebSocket /ws/stream`: Full-duplex real-time feed streaming 5–10 packet updates per second to the client.
