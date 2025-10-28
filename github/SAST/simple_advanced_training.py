"""
Simple Advanced SAST Training Script
Trains a model with advanced features that actually "thinks" about security
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_curve, auc
import joblib

# Try to import alternative algorithms
try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# Import our custom modules
from advanced_sast_features import AdvancedSASTFeatureExtractor
from advanced_code_preprocessing import AdvancedCodePreprocessor

def compare_algorithms(X_train, X_test, y_train, y_test):
    """Compare different algorithms and return results"""
    algorithms = {
        'RandomForest': RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
    }
    
    # Add alternative algorithms if available
    if LIGHTGBM_AVAILABLE:
        algorithms['LightGBM'] = LGBMClassifier(
            n_estimators=200,
            max_depth=15,
            learning_rate=0.1,
            random_state=42,
            verbose=-1
        )
    
    if XGBOOST_AVAILABLE:
        algorithms['XGBoost'] = XGBClassifier(
            n_estimators=200,
            max_depth=15,
            learning_rate=0.1,
            random_state=42,
            eval_metric='logloss'
        )
    
    results = {}
    
    for name, model in algorithms.items():
        model.fit(X_train, y_train)
        
        # Predictions
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]
        
        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
        
        results[name] = {
            'model': model,
            'accuracy': accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'y_pred': y_pred,
            'y_proba': y_proba
        }
    
    return results

def plot_roc_curves(results, y_test, save_path="models/roc_curves.png"):
    """Plot ROC curves for all algorithms"""
    plt.figure(figsize=(10, 8))
    
    for name, result in results.items():
        fpr, tpr, _ = roc_curve(y_test, result['y_proba'])
        roc_auc = auc(fpr, tpr)
        
        plt.plot(fpr, tpr, label=f'{name} (AUC = {roc_auc:.3f})')
    
    plt.plot([0, 1], [0, 1], 'k--', label='Random')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curves Comparison')
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    
    # Save plot
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    
    return plt

def plot_confusion_matrix(y_test, y_pred, title="Confusion Matrix", save_path="models/confusion_matrix.png"):
    """Plot confusion matrix"""
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title(title)
    plt.colorbar()
    
    classes = ['Safe', 'Vulnerable']
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes)
    plt.yticks(tick_marks, classes)
    
    # Add text annotations
    thresh = cm.max() / 2.
    for i, j in np.ndindex(cm.shape):
        plt.text(j, i, format(cm[i, j], 'd'),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black")
    
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    
    # Save plot
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    
    return plt

def main():
    """Main training function with enhanced features"""
    try:
        # Load dataset from merged.zip
        merged_zip_path = "../../merged.zip"
        dataset_path = "../../FINAL_MERGED_SAST_DATASET.csv"
        
        if not os.path.exists(merged_zip_path):
            raise FileNotFoundError(f"merged.zip not found at: {merged_zip_path}")
        
        import zipfile
        with zipfile.ZipFile(merged_zip_path, 'r') as zip_ref:
            zip_ref.extractall("../../")
        
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset file not found after extraction: {dataset_path}")
        
        df = pd.read_csv(dataset_path)
        
        # Take a sample for training (adjust size as needed)
        sample_size = min(10000, len(df))
        df_sample = df.sample(n=sample_size, random_state=42)
        
        # Clean data
        df_sample = df_sample.dropna(subset=['code_snippet', 'label'])
        df_sample['code_snippet'] = df_sample['code_snippet'].astype(str)
        
        # Prepare data
        X = df_sample['code_snippet'].tolist()
        y = df_sample['label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Extract advanced features
        extractor = AdvancedSASTFeatureExtractor()
        X_train_features = extractor.extract_all_features(X_train)
        X_test_features = extractor.extract_all_features(X_test)
        
        # Handle NaN values
        X_train_features = X_train_features.fillna(0)
        X_test_features = X_test_features.fillna(0)
        
        # Compare different algorithms
        algorithm_results = compare_algorithms(X_train_features, X_test_features, y_train, y_test)
        
        # Find best algorithm
        best_algorithm = max(algorithm_results.keys(), key=lambda x: algorithm_results[x]['accuracy'])
        best_model = algorithm_results[best_algorithm]['model']
        best_accuracy = algorithm_results[best_algorithm]['accuracy']
        
        # Generate visualizations
        plot_roc_curves(algorithm_results, y_test)
        best_y_pred = algorithm_results[best_algorithm]['y_pred']
        plot_confusion_matrix(y_test, best_y_pred, f"Confusion Matrix - {best_algorithm}")
        
        # Save model with versioning
        os.makedirs("models", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_version = f"v1.0.{timestamp}"
        
        model_path = f"models/advanced_sast_model_{timestamp}.joblib"
        extractor_path = f"models/feature_extractor_{timestamp}.joblib"
        
        # Save best model and extractor
        joblib.dump(best_model, model_path)
        joblib.dump(extractor, extractor_path)
        
        # Also save latest versions
        joblib.dump(best_model, "models/advanced_sast_model.joblib")
        joblib.dump(extractor, "models/feature_extractor.joblib")
        
        # Save algorithm comparison results
        comparison_path = f"models/algorithm_comparison_{timestamp}.json"
        import json
        comparison_data = {
            'timestamp': timestamp,
            'model_version': model_version,
            'best_algorithm': best_algorithm,
            'results': {name: {
                'accuracy': float(result['accuracy']),
                'cv_mean': float(result['cv_mean']),
                'cv_std': float(result['cv_std'])
            } for name, result in algorithm_results.items()}
        }
        
        with open(comparison_path, 'w') as f:
            json.dump(comparison_data, f, indent=2)
        
        return best_model, extractor, best_accuracy
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, None, 0.0

if __name__ == "__main__":
    model, extractor, accuracy = main()
