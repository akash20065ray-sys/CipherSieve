"""
EncryptedFlow AI - Classical Machine Learning Baselines
Implements Random Forest and Gradient Boosted Trees (XGBoost / HistGradientBoosting)
for tabular classification on the 13 payload-agnostic network features.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os


class BaselineModels:
    """
    Manages classical tree-based models for benchmarking against deep neural architectures.
    Uses StandardScaler for tabular feature normalization.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.scaler = StandardScaler()

        # 1. Random Forest (100 estimators, max depth 8 to prevent overfitting)
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=4,
            random_state=self.random_state,
            n_jobs=-1
        )

        # 2. Gradient Boosted Trees (Histogram-based, robust and fast)
        self.gb_model = HistGradientBoostingClassifier(
            max_iter=100,
            max_depth=6,
            learning_rate=0.08,
            random_state=self.random_state
        )

        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """
        Fits the scaler and both baseline tree models on tabular features.
        Returns training performance metrics.
        """
        X_scaled = self.scaler.fit_transform(X)

        self.rf_model.fit(X_scaled, y)
        self.gb_model.fit(X_scaled, y)
        self.is_fitted = True

        rf_train_acc = float(self.rf_model.score(X_scaled, y))
        gb_train_acc = float(self.gb_model.score(X_scaled, y))

        return {
            "random_forest_train_acc": rf_train_acc,
            "gradient_boost_train_acc": gb_train_acc
        }

    def predict_rf(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Returns (predicted_classes, class_probabilities) for Random Forest."""
        if not self.is_fitted:
            raise RuntimeError("Baseline models are not fitted yet.")
        X_scaled = self.scaler.transform(X)
        preds = self.rf_model.predict(X_scaled)
        probs = self.rf_model.predict_proba(X_scaled)
        return preds, probs

    def predict_gb(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Returns (predicted_classes, class_probabilities) for Gradient Boosting."""
        if not self.is_fitted:
            raise RuntimeError("Baseline models are not fitted yet.")
        X_scaled = self.scaler.transform(X)
        preds = self.gb_model.predict(X_scaled)
        probs = self.gb_model.predict_proba(X_scaled)
        return preds, probs

    def save(self, output_dir: str = "weights") -> None:
        """Serializes models and scaler to disk."""
        os.makedirs(output_dir, exist_ok=True)
        joblib.dump(self.rf_model, os.path.join(output_dir, "random_forest.joblib"))
        joblib.dump(self.gb_model, os.path.join(output_dir, "gradient_boost.joblib"))
        joblib.dump(self.scaler, os.path.join(output_dir, "tabular_scaler.joblib"))

    def load(self, weights_dir: str = "weights") -> None:
        """Loads serialized models and scaler from disk."""
        self.rf_model = joblib.load(os.path.join(weights_dir, "random_forest.joblib"))
        self.gb_model = joblib.load(os.path.join(weights_dir, "gradient_boost.joblib"))
        self.scaler = joblib.load(os.path.join(weights_dir, "tabular_scaler.joblib"))
        self.is_fitted = True
