"""
EncryptedFlow AI - Deep Neural Network Architectures
Implements 1D-CNN, Bidirectional LSTM, and Hybrid CNN+BiLSTM in PyTorch.
Designed for line-rate, sub-millisecond CPU inference on early-flow packet sequences.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class Flow1DCNN(nn.Module):
    """
    1D-Convolutional Neural Network for local packet burst pattern extraction.
    Input shape: (batch_size, seq_len, num_features) where features = [size, iat, direction, window]
    """
    def __init__(self, num_classes: int = 5, in_features: int = 4, seq_len: int = 20):
        super().__init__()
        self.conv1 = nn.Conv1d(in_channels=in_features, out_channels=32, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(32)
        self.conv2 = nn.Conv1d(in_channels=32, out_channels=64, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(64)
        self.pool = nn.MaxPool1d(kernel_size=2)
        self.dropout = nn.Dropout(0.25)
        
        # Flatten size: 64 channels * (seq_len // 2)
        flatten_dim = 64 * (seq_len // 2)
        self.fc1 = nn.Linear(flatten_dim, 64)
        self.fc2 = nn.Linear(64, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Transpose from (B, L, C) to (B, C, L) for Conv1d
        x = x.transpose(1, 2)
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.relu(self.bn2(self.conv2(x)))
        x = self.pool(x)
        x = self.dropout(x)
        x = torch.flatten(x, 1)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        return self.fc2(x)


class FlowBiLSTM(nn.Module):
    """
    Bidirectional LSTM for capturing sequential packet transmission rhythms.
    Input shape: (batch_size, seq_len, num_features)
    """
    def __init__(self, num_classes: int = 5, in_features: int = 4, hidden_dim: int = 64):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=in_features,
            hidden_size=hidden_dim,
            num_layers=1,
            batch_first=True,
            bidirectional=True
        )
        self.dropout = nn.Dropout(0.25)
        # Bidirectional produces 2 * hidden_dim
        self.fc1 = nn.Linear(hidden_dim * 2, 64)
        self.fc2 = nn.Linear(64, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, L, C)
        lstm_out, _ = self.lstm(x)  # (B, L, 2 * hidden_dim)
        # Global max pooling across sequence dimension
        pooled = torch.max(lstm_out, dim=1)[0]
        x = self.dropout(pooled)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        return self.fc2(x)


class HybridCNNBiLSTM(nn.Module):
    """
    Combined Spatial-Temporal Architecture.
    1D-CNN extracts local micro-burst features -> BiLSTM learns macro-sequence rhythms.
    Parameters: ~68,000 (< 300 KB in memory).
    """
    def __init__(self, num_classes: int = 5, in_features: int = 4, seq_len: int = 20):
        super().__init__()
        # Stage 1: Local Feature Extraction (CNN)
        self.conv1 = nn.Conv1d(in_channels=in_features, out_channels=32, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(32)
        self.conv2 = nn.Conv1d(in_channels=32, out_channels=64, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(64)
        self.pool = nn.MaxPool1d(kernel_size=2)
        self.dropout = nn.Dropout(0.2)

        # Stage 2: Temporal Sequence Modeling (BiLSTM)
        # Input to LSTM will have 64 channels per step
        self.lstm = nn.LSTM(
            input_size=64,
            hidden_size=64,
            num_layers=1,
            batch_first=True,
            bidirectional=True
        )

        # Stage 3: Classification Head
        self.fc1 = nn.Linear(128, 64)
        self.fc2 = nn.Linear(64, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, L, C) -> transpose to (B, C, L) for Conv1D
        c_in = x.transpose(1, 2)
        c_out = F.relu(self.bn1(self.conv1(c_in)))
        c_out = F.relu(self.bn2(self.conv2(c_out)))
        c_out = self.pool(c_out)  # Shape: (B, 64, L // 2)
        c_out = self.dropout(c_out)

        # Transpose back to (B, L // 2, 64) for LSTM
        lstm_in = c_out.transpose(1, 2)
        lstm_out, _ = self.lstm(lstm_in)  # Shape: (B, L // 2, 128)

        # Temporal mean pooling
        pooled = torch.mean(lstm_out, dim=1)
        dense = F.relu(self.fc1(pooled))
        dense = self.dropout(dense)
        return self.fc2(dense)
