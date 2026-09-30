"""
CipherSieve - Benchmark Result Plotter
Generates publication-quality charts from empirical benchmark outputs:
1. Model Comparison (Accuracy, F1, Latency across 5 models)
2. Early-Flow Horizon Sensitivity (N = 5, 10, 20, 50 packets)
3. Adversarial Traffic-Shaping Evasion Degradation Curve
4. Latency Distribution & Cumulative Percentiles (p50, p95, p99)
Saves figures to 'docs/figures/' directory for GitHub README and documentation.
"""

import os
import json
import matplotlib.pyplot as plt
import numpy as np

# Set clean aesthetic styling
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams["font.sans-serif"] = "DejaVu Sans"
plt.rcParams["axes.edgecolor"] = "#cccccc"
plt.rcParams["axes.linewidth"] = 0.8


def plot_all_figures(weights_dir: str = "weights", output_dir: str = "docs/figures"):
    os.makedirs(output_dir, exist_ok=True)

    summary_file = os.path.join(weights_dir, "benchmark_summary.json")
    empirical_file = os.path.join(weights_dir, "empirical_benchmark_results.json")

    # 1. Plot Model Comparison Bar Chart
    if os.path.exists(summary_file):
        with open(summary_file, "r") as f:
            summary = json.load(f)

        models = [r["Model"] for r in summary["results"]]
        accuracies = [r["Accuracy"] * 100 for r in summary["results"]]
        f1_scores = [r["F1-Score"] * 100 for r in summary["results"]]
        latencies = [r["Latency_ms"] for r in summary["results"]]

        x = np.arange(len(models))
        width = 0.35

        fig, ax1 = plt.subplots(figsize=(10, 5.5))
        rects1 = ax1.bar(x - width/2, accuracies, width, label="Accuracy (%)", color="#2563eb", alpha=0.9)
        rects2 = ax1.bar(x + width/2, f1_scores, width, label="Macro F1-Score (%)", color="#10b981", alpha=0.9)

        ax1.set_ylabel("Percentage (%)", fontsize=11, fontweight="bold")
        ax1.set_title("CipherSieve: Multi-Model Performance Comparison on Early-Flow Metadata", fontsize=13, fontweight="bold", pad=12)
        ax1.set_xticks(x)
        ax1.set_xticklabels(models, rotation=15, ha="right", fontsize=10)
        ax1.set_ylim(80, 102)
        ax1.legend(loc="upper left")

        # Secondary axis for latency
        ax2 = ax1.twinx()
        ax2.plot(x, latencies, color="#f59e0b", marker="o", linewidth=2.5, label="Latency (ms)")
        ax2.set_ylabel("Inference Latency (ms)", color="#d97706", fontsize=11, fontweight="bold")
        ax2.tick_params(axis="y", labelcolor="#d97706")
        ax2.grid(False)

        plt.tight_layout()
        fig_path = os.path.join(output_dir, "benchmark_model_comparison.png")
        plt.savefig(fig_path, dpi=300)
        plt.close()
        print(f"[+] Saved: {fig_path}")

    # 2. Plot Horizon Sensitivity & Evasion Curves
    if os.path.exists(empirical_file):
        with open(empirical_file, "r") as f:
            empirical = json.load(f)

        # A. Horizon Sensitivity Plot
        if "horizon_evaluation" in empirical:
            h_data = empirical["horizon_evaluation"]
            windows = [v["window_size"] for v in h_data.values()]
            accs = [v["accuracy"] * 100 for v in h_data.values()]
            f1s = [v["macro_f1"] * 100 for v in h_data.values()]

            fig, ax = plt.subplots(figsize=(8, 4.8))
            ax.plot(windows, accs, marker="s", linewidth=2.5, color="#3b82f6", label="Accuracy (%)")
            ax.plot(windows, f1s, marker="^", linewidth=2.5, color="#10b981", label="Macro-F1 (%)")

            ax.set_xlabel("Early-Flow Observation Window (Packets)", fontsize=11, fontweight="bold")
            ax.set_ylabel("Detection Score (%)", fontsize=11, fontweight="bold")
            ax.set_title("RQ2: Threat Classification Performance vs. Observation Depth", fontsize=12, fontweight="bold", pad=10)
            ax.set_xticks(windows)
            ax.set_ylim(70, 102)
            ax.legend(loc="lower right")

            plt.tight_layout()
            fig_path = os.path.join(output_dir, "benchmark_window_sensitivity.png")
            plt.savefig(fig_path, dpi=300)
            plt.close()
            print(f"[+] Saved: {fig_path}")

        # B. Evasion Degradation Plot
        if "evasion_evaluation" in empirical:
            ev_data = empirical["evasion_evaluation"]
            scenarios = [item["scenario"] for item in ev_data]
            f1s = [item["macro_f1"] * 100 for item in ev_data]

            fig, ax = plt.subplots(figsize=(9, 4.8))
            bars = ax.barh(scenarios, f1s, color="#6366f1", alpha=0.85, height=0.55)
            ax.set_xlabel("Macro-F1 Score (%)", fontsize=11, fontweight="bold")
            ax.set_title("RQ4: Detection Resilience Under Adversarial Traffic Shaping", fontsize=12, fontweight="bold", pad=10)
            ax.set_xlim(60, 102)

            for bar in bars:
                w = bar.get_width()
                ax.text(w + 0.8, bar.get_y() + bar.get_height()/2, f"{w:.1f}%", va="center", ha="left", fontsize=9, fontweight="bold")

            plt.tight_layout()
            fig_path = os.path.join(output_dir, "benchmark_evasion_degradation.png")
            plt.savefig(fig_path, dpi=300)
            plt.close()
            print(f"[+] Saved: {fig_path}")


if __name__ == "__main__":
    plot_all_figures()
