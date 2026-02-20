"""
extract_phishing_urls.py — Extract real phishing URLs from Kaggle dataset
Creates a production-ready phishing_urls.csv blacklist
"""

import os
import pandas as pd

DATASET_PATH = os.path.join(os.path.dirname(__file__), "data", "malicious_phish.csv")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "phishing_urls.csv")

def extract_phishing_urls(max_urls=10000):
    """
    Extract actual phishing URLs from Kaggle dataset.
    
    Args:
        max_urls: Maximum number of phishing URLs to extract (default: 10000)
    """
    print(f"Loading dataset from: {DATASET_PATH}")
    
    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}")
        print("Please run: kaggle datasets download -d sid321axn/malicious-urls-dataset -p backend/data --unzip")
        return
    
    # Load dataset
    df = pd.read_csv(DATASET_PATH)
    print(f"Total URLs in dataset: {len(df):,}")
    
    # Filter only phishing URLs
    phishing_df = df[df['type'] == 'phishing'].copy()
    print(f"Total phishing URLs: {len(phishing_df):,}")
    
    # Take a sample if we have more than max_urls
    if len(phishing_df) > max_urls:
        phishing_df = phishing_df.sample(n=max_urls, random_state=42)
        print(f"Sampled {max_urls:,} phishing URLs for blacklist")
    
    # Keep only the URL column
    output_df = phishing_df[['url']].copy()
    
    # Save to CSV
    output_df.to_csv(OUTPUT_PATH, index=False)
    print(f"\n✅ SUCCESS: Saved {len(output_df):,} phishing URLs to {OUTPUT_PATH}")
    print(f"\nFirst 10 URLs:")
    for i, url in enumerate(output_df['url'].head(10), 1):
        print(f"  {i}. {url}")
    
    return len(output_df)


if __name__ == "__main__":
    print("=" * 70)
    print("  VerifyFirst — Phishing URL Blacklist Generator")
    print("=" * 70)
    print()
    
    # Extract 10,000 real phishing URLs (adjust as needed)
    count = extract_phishing_urls(max_urls=10000)
    
    print("\n" + "=" * 70)
    print(f"Blacklist ready with {count:,} real phishing URLs from Kaggle dataset")
    print("=" * 70)
