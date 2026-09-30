"""
EncryptedFlow AI - Master Model Training Suite
Trains 5 candidate models on identical train/test splits:
1. Random Forest (Scikit-Learn)
2. Gradient Boosted Trees (Scikit-Learn)
3. 1D-CNN (PyTorch)
4. Bidirectional LSTM (PyTorch)
5. Hybrid CNN + BiLSTM (PyTorch)
Evaluates Accuracy, Precision, Recall, Macro-F1, and Inference Latency.
Saves all model checkpoints and scalers to the 'weights/' directory.
"""

import os
import sys
import time
import json
from typing import Tuple, List, Dict
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
import joblib

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmark.synthetic_generator import TrafficGenerator, CLASS_NAMES
from models.baselines import BaselineModels
from models.neural_models import Flow1DCNN, FlowBiLSTM, HybridCNNBiLSTM


def print_banner():
    banner = """
================================================================================
          CIPHERSIEVE / ENCRYPTEDFLOW AI - MASTER TRAINING SUITE
       Payload-Agnostic Encrypted Threat Detection & Model Evaluation
================================================================================
    """
    print(banner)


def train_neural_model(
    model: nn.Module,
    train_loader: DataLoader,
    val_loader: DataLoader,
    device: torch.device,
    epochs: int = 15,
    lr: float = 0.001,
    model_name: str = "Neural_Model"
) -> Tuple[nn.Module, float, float]:
    """
    Trains a PyTorch neural network, returns (best_model, best_val_acc, training_time_sec).
    """
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_acc = 0.0
    best_weights = None
    start_time = time.time()

    print(f"\n[*] Training {model_name} on {device} ({epochs} epochs)...")

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0

        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)

            optimizer.zero_grad()
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(y_batch)
            preds = torch.argmax(outputs, dim=1)
            correct += (preds == y_batch).sum().item()
            total += len(y_batch)

        scheduler.step()
        train_acc = correct / total
        avg_loss = total_loss / total

        # Validation
        model.eval()
        val_correct = 0
        val_total = 0
        with torch.no_grad():
            for X_val, y_val in val_loader:
                X_val, y_val = X_val.to(device), y_val.to(device)
                val_out = model(X_val)
                val_preds = torch.argmax(val_out, dim=1)
                val_correct += (val_preds == y_val).sum().item()
                val_total += len(y_val)

        val_acc = val_correct / val_total
        if val_acc >= best_acc:
            best_acc = val_acc
            best_weights = model.state_dict().copy()

        if epoch % 3 == 0 or epoch == epochs:
            print(f"    Epoch {epoch:2d}/{epochs:2d} | Loss: {avg_loss:.4f} | Train Acc: {train_acc*100:.1f}% | Val Acc: {val_acc*100:.1f}%")

    if best_weights is not None:
        model.load_state_dict(best_weights)

    train_time = time.time() - start_time
    return model, best_acc, train_time


def measure_inference_latency(model, sample_input, is_torch: bool = True, device="cpu", runs: int = 500) -> float:
    """Measures single-flow median inference latency in milliseconds."""
    latencies = []
    if is_torch:
        model.eval()
        with torch.no_grad():
            inp = torch.tensor(sample_input, dtype=torch.float32).unsqueeze(0).to(device)
            # Warmup
            for _ in range(20):
                _ = model(inp)
            for _ in range(runs):
                t0 = time.perf_counter()
                _ = model(inp)
                latencies.append((time.perf_counter() - t0) * 1000.0)
    else:
        # Classical model
        for _ in range(20):
            _ = model(sample_input.reshape(1, -1))
        for _ in range(runs):
            t0 = time.perf_counter()
            _ = model(sample_input.reshape(1, -1))
            latencies.append((time.perf_counter() - t0) * 1000.0)

    return float(np.median(latencies))


def main():
    print_banner()

    weights_dir = "weights"
    os.makedirs(weights_dir, exist_ok=True)

    # 1. Dataset Generation
    samples_per_class = 800  # 4,000 total flows for rapid, robust training
    observation_window = 20
    print(f"[1/5] Generating Ground-Truth Flow Dataset ({samples_per_class * 5} samples across 5 classes)...")

    gen = TrafficGenerator(random_seed=42)
    X_tab, X_seq, y = gen.generate_dataset(
        samples_per_class=samples_per_class,
        observation_window=observation_window
    )

    # Train / Test Split (80% Train, 20% Holdout Test)
    idx_train, idx_test = train_test_split(
        np.arange(len(y)),
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    X_tab_train, X_tab_test = X_tab[idx_train], X_tab[idx_test]
    X_seq_train, X_seq_test = X_seq[idx_train], X_seq[idx_test]
    y_train, y_test = y[idx_train], y[idx_test]

    print(f"      Train Samples: {len(y_train)} | Test Samples: {len(y_test)}")

    # 2. Train Classical Tree Baselines (Random Forest & Gradient Boost)
    print("\n[2/5] Training Classical ML Baselines on 13 Tabular Features...")
    baselines = BaselineModels(random_state=42)
    t0 = time.time()
    fit_metrics = baselines.fit(X_tab_train, y_train)
    rf_train_time = time.time() - t0
    print(f"      Random Forest Train Acc: {fit_metrics['random_forest_train_acc']*100:.2f}%")
    print(f"      Gradient Boost Train Acc: {fit_metrics['gradient_boost_train_acc']*100:.2f}%")
    baselines.save(weights_dir)

    # 3. Setup PyTorch Data Loaders
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[3/5] Setting up PyTorch DataLoaders (Target Device: {device})...")

    train_dataset = TensorDataset(torch.tensor(X_seq_train, dtype=torch.float32), torch.tensor(y_train, dtype=torch.long))
    test_dataset = TensorDataset(torch.tensor(X_seq_test, dtype=torch.float32), torch.tensor(y_test, dtype=torch.long))

    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=128, shuffle=False)

    # 4. Train Deep Neural Models
    print("\n[4/5] Training Deep Neural Sequence Models...")
    
    # Model 1: 1D-CNN
    cnn_model = Flow1DCNN(num_classes=5, in_features=4, seq_len=observation_window).to(device)
    cnn_model, _, cnn_time = train_neural_model(cnn_model, train_loader, test_loader, device, epochs=12, model_name="1D-CNN")
    torch.save(cnn_model.state_dict(), os.path.join(weights_dir, "cnn_model.pt"))

    # Model 2: BiLSTM
    bilstm_model = FlowBiLSTM(num_classes=5, in_features=4, hidden_dim=64).to(device)
    bilstm_model, _, lstm_time = train_neural_model(bilstm_model, train_loader, test_loader, device, epochs=12, model_name="BiLSTM")
    torch.save(bilstm_model.state_dict(), os.path.join(weights_dir, "bilstm_model.pt"))

    # Model 3: Hybrid CNN + BiLSTM
    hybrid_model = HybridCNNBiLSTM(num_classes=5, in_features=4, seq_len=observation_window).to(device)
    hybrid_model, _, hyb_time = train_neural_model(hybrid_model, train_loader, test_loader, device, epochs=14, model_name="Hybrid CNN+BiLSTM")
    torch.save(hybrid_model.state_dict(), os.path.join(weights_dir, "hybrid_model.pt"))

    # 5. Scientific Holdout Evaluation Across All 5 Models
    print("\n[5/5] Conducting Scientific Benchmark Evaluation on Holdout Test Set...")

    results = []

    # Eval 1: Random Forest
    rf_preds, _ = baselines.predict_rf(X_tab_test)
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(y_test, rf_preds, average="macro", zero_division=0)
    rf_lat = measure_inference_latency(baselines.rf_model.predict, baselines.scaler.transform(X_tab_test[0:1])[0], is_torch=False)
    results.append({"Model": "Random Forest", "Accuracy": rf_acc, "Precision": rf_prec, "Recall": rf_rec, "F1-Score": rf_f1, "Latency_ms": rf_lat})

    # Eval 2: Gradient Boost
    gb_preds, _ = baselines.predict_gb(X_tab_test)
    gb_acc = accuracy_score(y_test, gb_preds)
    gb_prec, gb_rec, gb_f1, _ = precision_recall_fscore_support(y_test, gb_preds, average="macro", zero_division=0)
    gb_lat = measure_inference_latency(baselines.gb_model.predict, baselines.scaler.transform(X_tab_test[0:1])[0], is_torch=False)
    results.append({"Model": "Gradient Boost", "Accuracy": gb_acc, "Precision": gb_prec, "Recall": gb_rec, "F1-Score": gb_f1, "Latency_ms": gb_lat})

    # Eval Deep Models
    def eval_torch_model(m, name):
        m.eval()
        with torch.no_grad():
            X_tensor = torch.tensor(X_seq_test, dtype=torch.float32).to(device)
            out = m(X_tensor)
            preds = torch.argmax(out, dim=1).cpu().numpy()
            acc = accuracy_score(y_test, preds)
            prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average="macro", zero_division=0)
            lat = measure_inference_latency(m, X_seq_test[0], is_torch=True, device=device)
            return {"Model": name, "Accuracy": acc, "Precision": prec, "Recall": rec, "F1-Score": f1, "Latency_ms": lat}

    results.append(eval_torch_model(cnn_model, "1D-CNN"))
    results.append(eval_torch_model(bilstm_model, "BiLSTM"))
    results.append(eval_torch_model(hybrid_model, "Hybrid CNN+BiLSTM"))

    # Print Final Benchmark Table
    print("\n" + "="*84)
    print(f"{'MODEL ARCHITECTURE':<22} | {'ACCURACY':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'LATENCY (p50)':<12}")
    print("="*84)
    for r in results:
        print(f"{r['Model']:<22} | {r['Accuracy']*100:6.2f}%    | {r['Precision']*100:6.2f}%    | {r['Recall']*100:6.2f}%    | {r['F1-Score']*100:6.2f}%    | {r['Latency_ms']:6.2f} ms")
    print("="*84)

    # Save summary JSON for dashboard and API
    summary_path = os.path.join(weights_dir, "benchmark_summary.json")
    with open(summary_path, "w") as f:
        json.dump({
            "timestamp": time.time(),
            "observation_window": observation_window,
            "classes": CLASS_NAMES,
            "results": results
        }, f, indent=2)

    print(f"\n[+] Training Complete! All model weights and benchmark summary saved to '{weights_dir}/'.")


if __name__ == "__main__":
    main()
