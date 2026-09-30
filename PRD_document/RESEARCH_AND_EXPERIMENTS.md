# Scientific Methodology & Experimental Research Plan
## Project: EncryptedFlow AI
### Subtitle: Empirical Investigation of Early-Flow Metadata for Threat Detection in Encrypted Networks

---

## 1. Research Objectives & Problem Formulation

Encrypted traffic classification literature frequently makes broad performance claims based on offline, synthetic, or closed-world benchmarks. 

The goal of this research plan is to replace assumptions with **empirical experimentation**, structured around five core Research Questions (RQs):

* **RQ1 (Detection Feasibility)**: *Can statistical and sequential transport-layer metadata distinguish benign encrypted sessions from malicious flows without payload inspection?*
* **RQ2 (Observation Window Sensitivity)**: *What is the relationship between classification performance and observation depth across early-flow windows of $N \in \{5, 10, 20, 50\}$ packets?*
* **RQ3 (Inductive Bias & Model Suitability)**: *Do deep neural sequence architectures (1D-CNN, BiLSTM, Hybrid) demonstrate statistically meaningful performance gains over classical tree-based ensembles (Random Forest, XGBoost) on early-flow metadata?*
* **RQ4 (Adversarial Robustness & Evasion)**: *How resilient is the classification pipeline when an adversary deliberately morphs traffic via random packet padding ($0 - 200\text{ bytes}$) and inter-packet transmission jitter ($10 - 100\text{ms}$)?*
* **RQ5 (Feature Attribution & Ablation)**: *Which subset of the 13 observable features contributes the highest marginal utility to threat discrimination?*

---

## 2. Traffic Flow Taxonomy & Ground-Truth Profiles

The benchmark suite models five distinct traffic behavioral profiles grounded in real-world networking dynamics:

| Profile Class | Category | Dominant Physical Characteristics |
| :--- | :--- | :--- |
| **`BENIGN_WEB`** | Normal User HTTPS | Bimodal packet size distribution (small TCP ACKs $\sim 64\text{B}$, large TLS records $\sim 1400\text{B}$); bursty arrival followed by human think-time ($0.2 - 2.0\text{s}$ pauses). |
| **`BENIGN_STREAM`**| Video / Streaming | High continuous downstream volume; uniform inter-arrival intervals; large sustained packet sizes ($\sim 1300 - 1500\text{B}$); steady TCP window updates. |
| **`SCAN_RECON`** | Port / Service Scan | Rapid train of small packets ($\sim 40 - 74\text{B}$); low or zero inter-arrival variance ($< 5\text{ms}$); high forward-to-backward packet ratio; frequent SYN/RST flags. |
| **`DATA_EXFIL`** | Encrypted Data Theft | Severe directional asymmetry (forward byte ratio $> 10\times$ backward); continuous maximum transmission unit (MTU) upstream pushes; minimal pauses. |
| **`C2_BEACON`** | Botnet Heartbeat | Highly periodic, deterministic timing intervals ($\Delta t \approx \text{const}$); small fixed payload sizes; low total data volume per session. |

---

## 3. Mathematical Definition of the 13 Feature Dimensions

Let a network flow observation window be defined as a sequence of $N$ packets:
$$\mathcal{W}_N = \{ p_1, p_2, \dots, p_N \}$$
where each packet is represented by timestamp $t_i$, size $s_i$ (bytes), direction $d_i \in \{+1, -1\}$, and advertised TCP window $w_i$.

1. **Mean Packet Size ($\mu_s$)**: $\mu_s = \frac{1}{N} \sum_{i=1}^N s_i$
2. **Standard Deviation of Packet Size ($\sigma_s$)**: $\sigma_s = \sqrt{\frac{1}{N-1} \sum_{i=1}^N (s_i - \mu_s)^2}$
3. **Max Packet Size ($s_{\max}$)**: $\max_{i} (s_i)$
4. **Min Packet Size ($s_{\min}$)**: $\min_{i} (s_i)$
5. **Mean Inter-Arrival Time ($\mu_{\Delta t}$)**: $\mu_{\Delta t} = \frac{1}{N-1} \sum_{i=2}^N (t_i - t_{i-1})$
6. **Standard Deviation of IAT ($\sigma_{\Delta t}$)**: $\sigma_{\Delta t} = \sqrt{\frac{1}{N-2} \sum_{i=2}^N (\Delta t_i - \mu_{\Delta t})^2}$
7. **Max Inter-Arrival Time ($\Delta t_{\max}$)**: $\max_i (\Delta t_i)$
8. **Flow Observation Duration ($T$)**: $T = t_N - t_1$
9. **Forward/Backward Packet Ratio ($R_{\text{pkt}}$)**: $\frac{|\{p_i : d_i = +1\}|}{\max(1, |\{p_i : d_i = -1\}|)}$
10. **Forward/Backward Byte Ratio ($R_{\text{byte}}$)**: $\frac{\sum_{d_i=+1} s_i}{\max(1, \sum_{d_i=-1} s_i)}$
11. **Packet Rate ($V_{\text{pkt}}$)**: $\frac{N}{\max(T, \epsilon)}$
12. **Byte Rate ($V_{\text{byte}}$)**: $\frac{\sum s_i}{\max(T, \epsilon)}$
13. **Mean TCP Window ($\mu_w$)**: $\frac{1}{N} \sum_{i=1}^N w_i$

---

## 4. Experimental Protocols

### Experiment 1: Model Architecture Comparative Evaluation
* **Objective**: Evaluate 5 distinct model families on identical stratified $k$-fold cross-validation splits ($k=5$).
* **Candidate Models**:
  1. **Random Forest**: 100 estimators, Gini impurity criterion, max depth 8.
  2. **XGBoost**: Gradient boosted decision trees, learning rate 0.1, max depth 6.
  3. **1D-CNN**: 2 convolutional blocks (kernel size 3, ReLU, MaxPooling), Dropout (0.3), Dense projection.
  4. **BiLSTM**: 2-layer Bidirectional LSTM (hidden dimension 64), temporal attention pooling, Dense projection.
  5. **Hybrid CNN+BiLSTM**: 1D-CNN feature extraction feeding into BiLSTM temporal encoder.
* **Evaluation Metrics**:
  * Accuracy
  * Precision (Macro)
  * Recall (Macro)
  * Macro-F1 Score
  * False Positive Rate (FPR) on Benign Traffic

### Experiment 2: Early Detection Observation Horizon Sensitivity
* **Objective**: Measure performance degradation as observation horizon is constrained.
* **Test Windows**: $N \in \{5, 10, 20, 50\}$ packets.
* **Hypothesis**: Handshake packets ($N \le 10$) suffice for reconnaissance (Scanning) and burst attacks, whereas exfiltration and C2 beaconing require $N \ge 20$ to establish reliable timing variance.

### Experiment 3: Adversarial Traffic-Shaping & Evasion Stress Testing
* **Objective**: Quantify model resilience against an evasion-minded adversary.
* **Perturbation Injectors**:
  * **Timing Jitter**: $\Delta t_i' = \Delta t_i + \mathcal{U}(0, \delta_{\text{jitter}})$ where $\delta_{\text{jitter}} \in \{10\text{ms}, 50\text{ms}, 100\text{ms}\}$.
  * **Packet Padding**: $s_i' = \min(s_i + \mathcal{U}(0, \delta_{\text{pad}}), \text{MTU})$ where $\delta_{\text{pad}} \in \{50\text{B}, 100\text{B}, 200\text{B}\}$.
* **Analysis**: Plot F1-Score degradation curves as perturbation magnitude increases.

### Experiment 4: Feature Importance & Ablation Analysis
* **Objective**: Identify which physical signals carry the strongest discriminatory signal.
* **Ablation Sets**:
  1. All 13 Features (Full Baseline)
  2. Without Timing Features (Exclude IAT $\mu, \sigma, \max, T$)
  3. Without Volumetric Features (Exclude Size $\mu, \sigma, \max, \min$)
  4. Without Directional Features (Exclude $R_{\text{pkt}}, R_{\text{byte}}$)
  5. Only Timing + Size Features (Minimal Set)

### Experiment 5: End-to-End Latency Profiling
* **Objective**: Measure sub-component and cumulative latency across 1,000 continuous flow evaluations.
* **Measurement Breakdowns**:
  * $T_{\text{extraction}}$: Time to compute 13 features from packet buffer.
  * $T_{\text{inference}}$: Model forward pass execution time.
  * $T_{\text{evidence}}$: Time to generate explainability attribution.
  * $T_{\text{total}}$: Cumulative pipeline detection delay.
* **Reporting Standard**: Mean, Median ($p50$), 95th Percentile ($p95$), and 99th Percentile ($p99$).

---

## 5. Deliverables & Publication-Quality Artifacts
Upon completion of the benchmark execution, the system generates:
1. `benchmark_model_comparison.png`: Bar chart of Accuracy, F1, and Latency across all 5 models.
2. `benchmark_window_sensitivity.png`: Line plot of F1-Score across $N \in \{5, 10, 20, 50\}$.
3. `benchmark_evasion_degradation.png`: Curve showing accuracy retention under adversarial traffic shaping.
4. `benchmark_confusion_matrix.png`: Normalized confusion matrix across all 5 traffic profiles.
5. `benchmark_latency_distribution.png`: Histogram and CDF of $p50, p95, p99$ processing times.
