#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced SAST Training Script
Trains 2 models:
- Model A: Vulnerability Detection (Binary: Vuln vs Safe)
- Model B: Vulnerability Type Classification (Multi-class: SQLi, XSS, Command Injection, etc.)

Includes:
- Line number and context extraction
- Enhanced remediation for each vulnerability type
"""

import os
import sys
import ast
import re
import logging
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
import joblib
import warnings
warnings.filterwarnings("ignore")

# Import custom modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from advanced_sast_features import AdvancedSASTFeatureExtractor
from advanced_code_preprocessing import AdvancedCodePreprocessor
from vulnerability_remediation import VulnerabilityRemediator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enhanced_sast_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def extract_line_number_and_context(code_snippet: str, vulnerable_line: str = None) -> dict:
    """
    Extract line number and context from code snippet
    Returns dict with line_number, context_before, context_after, and vulnerable_line
    """
    lines = code_snippet.split('\n')
    
    # Try to find the vulnerable line if provided
    line_number = None
    context_before = []
    context_after = []
    vulnerable_line_text = None
    
    if vulnerable_line:
        # Find the line containing the vulnerable pattern
        for idx, line in enumerate(lines):
            if vulnerable_line.strip() in line:
                line_number = idx + 1  # 1-indexed
                vulnerable_line_text = line.strip()
                # Get context (3 lines before and after)
                context_before = lines[max(0, idx-3):idx]
                context_after = lines[idx+1:min(len(lines), idx+4)]
                break
    
    # If no specific vulnerable line, find the most suspicious line
    if line_number is None:
        suspicious_patterns = [
            r'SELECT.*\+',
            r'execute.*\+',
            r'document\.write',
            r'innerHTML',
            r'os\.system',
            r'subprocess\.',
            r'eval\(',
            r'open\(',
            r'file\(',
        ]
        
        for idx, line in enumerate(lines):
            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    line_number = idx + 1
                    vulnerable_line_text = line.strip()
                    context_before = lines[max(0, idx-3):idx]
                    context_after = lines[idx+1:min(len(lines), idx+4)]
                    break
            if line_number:
                break
    
    # Default to first line if nothing found
    if line_number is None:
        line_number = 1
        vulnerable_line_text = lines[0].strip() if lines else ""
        context_after = lines[1:min(len(lines), 4)] if len(lines) > 1 else []
    
    return {
        'line_number': line_number,
        'vulnerable_line': vulnerable_line_text,
        'context_before': '\n'.join(context_before),
        'context_after': '\n'.join(context_after),
        'full_context': '\n'.join(context_before + [vulnerable_line_text] + context_after)
    }

def plot_confusion_matrix(y_true, y_pred, labels, title, save_path):
    """Plot and save confusion matrix"""
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=labels, yticklabels=labels)
    plt.title(title)
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    logger.info(f"Saved confusion matrix to {save_path}")
    
def get_model_summary():
    """Get summary of all available models"""
    models = {}
    
    # Check for SAST models
    sast_models_path = "github/SAST/models"
    if os.path.exists(sast_models_path):
        for file in os.listdir(sast_models_path):
            if file.endswith(('.joblib', '.pkl')):
                file_path = os.path.join(sast_models_path, file)
                size = os.path.getsize(file_path) / (1024 * 1024)  # MB
                models[file] = {
                    'path': file_path,
                    'size_mb': round(size, 2),
                    'type': 'SAST'
                }
    
    # Check for SCA models
    sca_models_path = "sca_simple_model_training"
    if os.path.exists(sca_models_path):
        for file in os.listdir(sca_models_path):
            if file.endswith(('.joblib', '.pkl')):
                file_path = os.path.join(sca_models_path, file)
                size = os.path.getsize(file_path) / (1024 * 1024)  # MB
                models[file] = {
                    'path': file_path,
                    'size_mb': round(size, 2),
                    'type': 'SCA'
                }
    
    return models

def train_model_A(X_features, y, output_dir="models"):
    """
    Train Model A: Binary Vulnerability Detection
    """
    logger.info("=" * 60)
    logger.info("Training Model A: Binary Vulnerability Detection")
    logger.info("=" * 60)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_features, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Training set: {X_train.shape[0]}, Test set: {X_test.shape[0]}")
    logger.info(f"Class distribution - Safe: {(y == 0).sum()}, Vulnerable: {(y == 1).sum()}")
    
    # Train Random Forest
    logger.info("Training RandomForest classifier...")
    model_rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    model_rf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model_rf.predict(X_test)
    y_proba = model_rf.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='binary')
    recall = recall_score(y_test, y_pred, average='binary')
    f1 = f1_score(y_test, y_pred, average='binary')
    roc_auc = roc_auc_score(y_test, y_proba)
    
    logger.info(f"\nModel A Performance:")
    logger.info(f"  Accuracy:  {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall:    {recall:.4f}")
    logger.info(f"  F1-Score:  {f1:.4f}")
    logger.info(f"  ROC-AUC:   {roc_auc:.4f}")
    logger.info(f"\nClassification Report:\n{classification_report(y_test, y_pred, target_names=['Safe', 'Vulnerable'])}")
    
    # Plot confusion matrix
    plot_confusion_matrix(y_test, y_pred, [0, 1], 
                        "Model A: Vulnerability Detection",
                        os.path.join(output_dir, "cm_modelA_vuln.png"))
    
    # Save model
    model_path = os.path.join(output_dir, "model_A_vuln.joblib")
    joblib.dump(model_rf, model_path)
    logger.info(f"[SUCCESS] Model A saved to {model_path}")
    
    return model_rf

def train_model_B(X_features, y_types, output_dir="models"):
    """
    Train Model B: Multi-class Vulnerability Type Classification
    """
    logger.info("=" * 60)
    logger.info("Training Model B: Vulnerability Type Classification")
    logger.info("=" * 60)
    
    # Filter to only vulnerable samples (exclude safe samples)
    mask = y_types != 'Safe'
    X_vuln = X_features[mask]
    y_vuln = y_types[mask]
    
    logger.info(f"Vulnerable samples: {len(X_vuln)}")
    # Convert to Series for value_counts or use unique
    if isinstance(y_vuln, np.ndarray):
        unique, counts = np.unique(y_vuln, return_counts=True)
        dist_dict = dict(zip(unique, counts))
        logger.info(f"Vulnerability type distribution:\n{dist_dict}")
    else:
        logger.info(f"Vulnerability type distribution:\n{y_vuln.value_counts()}")
    
    # Encode labels
    from sklearn.preprocessing import LabelEncoder
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_vuln)
    class_names = label_encoder.classes_
    
    logger.info(f"Classes: {list(class_names)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_vuln, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    logger.info(f"Training set: {X_train.shape[0]}, Test set: {X_test.shape[0]}")
    
    # Train Random Forest
    logger.info("Training RandomForest classifier...")
    model_rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    model_rf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model_rf.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='macro')
    recall = recall_score(y_test, y_pred, average='macro')
    f1_macro = f1_score(y_test, y_pred, average='macro')
    f1_micro = f1_score(y_test, y_pred, average='micro')
    
    logger.info(f"\nModel B Performance:")
    logger.info(f"  Accuracy:  {accuracy:.4f}")
    logger.info(f"  Precision (macro): {precision:.4f}")
    logger.info(f"  Recall (macro):    {recall:.4f}")
    logger.info(f"  F1-Score (macro):  {f1_macro:.4f}")
    logger.info(f"  F1-Score (micro):  {f1_micro:.4f}")
    
    # Get unique classes in predictions and labels
    unique_pred = np.unique(y_pred)
    unique_test = np.unique(y_test)
    unique_all = np.unique(np.concatenate([unique_pred, unique_test]))
    
    # Create report with only classes that appear
    report_class_names = [class_names[i] for i in unique_all]
    logger.info(f"\nClassification Report:\n{classification_report(y_test, y_pred, labels=unique_all, target_names=report_class_names, zero_division=0)}")
    
    # Plot confusion matrix
    plot_confusion_matrix(y_test, y_pred, list(range(len(class_names))),
                        "Model B: Vulnerability Type Classification",
                        os.path.join(output_dir, "cm_modelB_types.png"))
    
    # Save model and label encoder
    model_path = os.path.join(output_dir, "model_B_types.joblib")
    encoder_path = os.path.join(output_dir, "label_encoder_B.joblib")
    
    joblib.dump(model_rf, model_path)
    joblib.dump(label_encoder, encoder_path)
    logger.info(f"[SUCCESS] Model B saved to {model_path}")
    logger.info(f"[SUCCESS] Label encoder saved to {encoder_path}")
    
    return model_rf, label_encoder

def main():
    """Main training function"""
    logger.info("Starting Enhanced SAST Model Training")
    logger.info("=" * 60)
    
    try:
        # Load dataset
        dataset_path = "Useful_SAST_Dataset/FINAL_MERGED_SAST_DATASET.csv"
        if not os.path.exists(dataset_path):
            dataset_path = "../../Useful_SAST_Dataset/FINAL_MERGED_SAST_DATASET.csv"
        
        logger.info(f"Loading dataset from: {dataset_path}")
        df = pd.read_csv(dataset_path, low_memory=False)
        
        logger.info(f"Loaded {len(df)} samples")
        
        # Clean data
        df = df.dropna(subset=['code_snippet', 'label'])
        df['code_snippet'] = df['code_snippet'].astype(str)
        
        # Prepare labels
        # Model A: Binary classification
        y_A = df['label'].values
        
        # Model B: Vulnerability type classification
        # Map vuln_type to a standard format
        if 'vuln_type' in df.columns:
            y_B = df['vuln_type'].fillna('Safe').values
        elif 'vulnerability type' in df.columns:
            y_B = df['vulnerability type'].fillna('Safe').values
        else:
            # If no vuln_type column, mark non-vulnerable as 'Safe'
            y_B = np.where(y_A == 0, 'Safe', 'Unknown')
        
        # Normalize vulnerability type names
        vuln_type_map = {
            'Cross-Site Scripting (XSS)': 'XSS',
            'SQL Injection': 'SQL Injection',
            'Command Injection': 'Command Injection',
            'Insecure Deserialization': 'Insecure Deserialization',
            'Path Traversal': 'Path Traversal',
        }
        y_B = np.array([vuln_type_map.get(v, v) if v in vuln_type_map else v for v in y_B])
        
        logger.info(f"Vulnerability type distribution:\n{pd.Series(y_B).value_counts()}")
        
        # Sample data if too large
        max_samples = 10000
        if len(df) > max_samples:
            logger.info(f"Sampling {max_samples} samples for training...")
            df_sample = df.sample(n=max_samples, random_state=42)
            X = df_sample['code_snippet'].tolist()
            y_A = df_sample['label'].values
            y_B = np.array([vuln_type_map.get(v, v) if v in vuln_type_map else v 
                           for v in df_sample.get('vuln_type', df_sample.get('vulnerability type', 'Safe')).fillna('Safe').values])
        else:
            X = df['code_snippet'].tolist()
        
        logger.info(f"Training on {len(X)} samples")
        logger.info(f"Model A - Safe: {(y_A == 0).sum()}, Vulnerable: {(y_A == 1).sum()}")
        
        # Extract features
        logger.info("Extracting advanced features...")
        extractor = AdvancedSASTFeatureExtractor()
        X_features = extractor.extract_all_features(X)
        X_features = X_features.fillna(0)
        
        logger.info(f"Extracted {X_features.shape[1]} features from {len(X)} samples")
        
        # Create output directory
        output_dir = "models"
        os.makedirs(output_dir, exist_ok=True)
        
        # Train Model A (Binary)
        model_A = train_model_A(X_features, y_A, output_dir)
        
        # Train Model B (Multi-class)
        model_B, label_encoder_B = train_model_B(X_features, y_B, output_dir)
        
        # Save complete bundle
        bundle_path = os.path.join(output_dir, "enhanced_sast_models.joblib")
        bundle = {
            'model_A': model_A,
            'model_B': model_B,
            'label_encoder_B': label_encoder_B,
            'feature_extractor': extractor,
            'remediator': VulnerabilityRemediator(),
            'model_version': f"v2.0.{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'training_timestamp': datetime.now().isoformat()
        }
        joblib.dump(bundle, bundle_path)
        logger.info(f"\n[SUCCESS] All models saved to {bundle_path}")
        
        logger.info("\n" + "=" * 60)
        logger.info("SUCCESS! Enhanced SAST Models Trained Successfully!")
        logger.info("=" * 60)
        logger.info("\nFeatures:")
        logger.info("- Model A: Binary vulnerability detection")
        logger.info("- Model B: Multi-class vulnerability type classification")
        logger.info("- Line number and context extraction")
        logger.info("- Enhanced remediation for each vulnerability type")
        
        return bundle
        
    except Exception as e:
        logger.error(f"ERROR during training: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    bundle = main()
    if bundle:
        logger.info("\n[SUCCESS] Training completed successfully!")
    else:
        logger.error("\n[ERROR] Training failed. Check the error messages above.")

