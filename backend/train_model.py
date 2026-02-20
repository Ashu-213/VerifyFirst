"""
train_model.py — Train and save the VerifyFirst phishing detection model.

Run ONCE before starting the server:
    python train_model.py

Uses real-world Kaggle dataset (651k URLs) for training.
Outputs: model.pkl
"""

import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features, features_to_vector, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "data", "malicious_phish.csv")


def normalize_url(url):
    """Ensure URL has a scheme for proper parsing."""
    url = str(url).strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def load_dataset(max_samples=None):
    """
    Load Kaggle dataset and convert to binary classification.
    
    Labels:
    - benign -> 0 (safe)
    - phishing, malware, defacement -> 1 (malicious)
    
    Args:
        max_samples: Optional limit for faster testing (None = use all data)
    
    Returns:
        X (numpy array), y (numpy array)
    """
    print(f"Loading dataset from: {DATASET_PATH}")
    
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"\n\nDataset not found: {DATASET_PATH}\n"
            "Please download it first:\n"
            "  kaggle datasets download -d sid321axn/malicious-urls-dataset "
            "-p backend/data --unzip\n"
        )
    
    df = pd.read_csv(DATASET_PATH)
    print(f"Total URLs loaded: {len(df):,}")
    print(f"\nOriginal distribution:")
    print(df['type'].value_counts())
    
    # Limit samples if specified (for testing)
    if max_samples and max_samples < len(df):
        df = df.sample(n=max_samples, random_state=42)
        print(f"\nUsing {max_samples:,} samples for faster training")
    
    # Convert to binary labels
    df['label'] = (df['type'] != 'benign').astype(int)
    
    print(f"\nBinary labels:")
    print(f"  Safe (benign):     {(df['label'] == 0).sum():,}")
    print(f"  Malicious (other): {(df['label'] == 1).sum():,}")
    
    # Extract features
    print("\nExtracting features from URLs...")
    X, y = [], []
    errors = 0
    
    for idx, row in df.iterrows():
        if idx % 50000 == 0 and idx > 0:
            print(f"  Processed {idx:,} / {len(df):,} URLs...")
        
        try:
            url = normalize_url(row['url'])
            features = extract_features(url)
            vector = features_to_vector(features)
            X.append(vector)
            y.append(row['label'])
        except Exception as e:
            errors += 1
            if errors <= 5:  # Show first few errors only
                print(f"  Warning: Failed to process URL '{row['url']}': {e}")
    
    print(f"\nFeature extraction complete!")
    print(f"  Successfully processed: {len(X):,}")
    print(f"  Errors (skipped): {errors}")
    
    return np.array(X), np.array(y)


def train():
    print("=" * 70)
    print("  VerifyFirst -- ML Model Training (Real Kaggle Dataset)")
    print("=" * 70)
    print(f"\nFeatures ({len(FEATURE_NAMES)}): {FEATURE_NAMES}\n")

    # Load real dataset
    # Use max_samples=50000 for quick testing, or None for full dataset
    X, y = load_dataset(max_samples=None)  # Change to 50000 for testing
    
    print(f"\n{'='*70}")
    print(f"Dataset ready: {len(X):,} samples")
    print(f"  Safe: {(y==0).sum():,}  |  Malicious: {(y==1).sum():,}")
    print(f"{'='*70}\n")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train):,} samples")
    print(f"Test set:     {len(X_test):,} samples\n")

    # Train model
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,  # Use all CPU cores
        verbose=1
    )

    print("Training RandomForest (this may take a few minutes)...")
    model.fit(X_train, y_train)

    # Evaluate
    print("\nEvaluating model on test set...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*70}")
    print(f"Test Accuracy: {acc:.2%}")
    print(f"{'='*70}\n")
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted")
    print(f"                 Safe   Malicious")
    print(f"Actual Safe      {cm[0][0]:<6} {cm[0][1]:<6}")
    print(f"       Malicious {cm[1][0]:<6} {cm[1][1]:<6}")

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"\n[SUCCESS] Model saved to: {MODEL_PATH}")

    # Feature importance
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print(f"\n{'='*70}")
    print("Top 10 Most Important Features:")
    print(f"{'='*70}")
    for i, (name, imp) in enumerate(importances[:10], 1):
        bar = "#" * int(imp * 60)
        print(f"{i:2}. {name:<30} {bar}  {imp:.4f}")
    
    print(f"\n{'='*70}")
    print("Training complete! Run the server with: uvicorn main:app --reload")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    train()
