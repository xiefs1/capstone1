#!/usr/bin/env python3
import os, json, argparse, sys
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
from packaging import version as V
from scipy import sparse as sp
import xgboost as xgb

# ---------- helpers ----------
def parse_args():
    ap = argparse.ArgumentParser(description="SCA inference with rules → JSON report")
    ap.add_argument("--input", help="CSV file with rows to scan (ecosystem,package_name,version ...)")
    ap.add_argument("--ecosystem", help="Single-mode: ecosystem, e.g. PyPI/npm/RubyGems")
    ap.add_argument("--package", help="Single-mode: package name")
    ap.add_argument("--version", help="Single-mode: current version")
    ap.add_argument("--meta", default="sca_latest_meta.json", help="Metadata JSON for latest versions")
    ap.add_argument("--train_meta", default="train_metadata.json", help="Training metadata JSON")
    ap.add_argument("--preproc", help="Path to preprocessed PKL (default from train_metadata.json)")
    ap.add_argument("--model", help="Path to model_xgb.json (default from train_metadata.json)")
    ap.add_argument("--out", default="report.json", help="Output JSON path")
    return ap.parse_args()

def load_train_assets(train_meta_path, preproc_override=None, model_override=None):
    with open(train_meta_path, "r", encoding="utf-8") as f:
        tmeta = json.load(f)

    preproc = preproc_override or tmeta.get("preprocess_pkl") or "sca_ml_ready_3class_preprocessed.pkl"
    model_path = model_override or tmeta.get("models", {}).get("xgb_path") or "model_xgb.json"

    bundle = joblib.load(preproc)
    # encoders from PKL
    ohe_ecosys = bundle["encoders"]["ohe_ecosystem"]
    ohe_sev    = bundle["encoders"]["ohe_severity"]
    hash_cfg   = bundle["encoders"]["feature_hasher_pkg"]
    num_cols   = bundle["columns_used"]["numeric"]
    feature_names = bundle["feature_names"]
    label_map = bundle["label_map"]

    # xgb model
    xgb_model = xgb.Booster()
    xgb_model.load_model(model_path)

    return {
        "ohe_ecosys": ohe_ecosys,
        "ohe_sev": ohe_sev,
        "hash_dims": int(hash_cfg["n_features"]),
        "num_cols": num_cols,
        "feature_names": feature_names,
        "label_map": label_map,
        "xgb_model": xgb_model,
    }

def load_latest_meta(meta_path):
    # expected shape: { "<ecosystem>": { "<package_name>": { "latest_version": "...", "latest_release_date": "...", "current_release_date": "..." }, ... } }
    if not os.path.exists(meta_path):
        return {}
    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_date_safe(x):
    if not x or pd.isna(x):
        return pd.NaT
    try:
        return pd.to_datetime(x, utc=True)
    except Exception:
        return pd.NaT

def version_tuple(s):
    try:
        v = V.parse(str(s))
        return getattr(v, "major", 0), getattr(v, "minor", 0), getattr(v, "micro", 0)
    except Exception:
        return (0, 0, 0)

def smart_gap_is_outdated(cur, lat):
    # R2: OUTDATED if major or minor differ; patch-only difference is OK
    try:
        ca, cb = V.parse(str(cur)), V.parse(str(lat))
        if ca.major != cb.major:
            return True
        if ca.minor != cb.minor:
            return True
        return False
    except Exception:
        return False

def build_single_row_df(ecosystem, package_name, version, meta_row):
    # meta_row may contain: latest_version, latest_release_date, current_release_date, is_synthetic
    latest_version = (meta_row or {}).get("latest_version")
    latest_release_date = (meta_row or {}).get("latest_release_date")
    current_release_date = (meta_row or {}).get("current_release_date")
    is_synthetic = (meta_row or {}).get("is_synthetic", 0)

    ver_major, ver_minor, ver_patch = version_tuple(version)
    lat_major, lat_minor, lat_patch = version_tuple(latest_version) if latest_version else (0,0,0)

    row = {
        "ecosystem": ecosystem or "UNKNOWN",
        "package_name": package_name or "unknown",
        "version": version or "0.0.0",
        "severity": "NONE",               # default if not provided
        "cvss_base_score": 0.0,
        "reference_count": 0.0,
        "is_vulnerable_Y": 0.0,
        "is_synthetic": float(is_synthetic),

        "ver_major": float(ver_major),
        "ver_minor": float(ver_minor),
        "ver_patch": float(ver_patch),
        "ver_is_pre": 0.0,

        "latest_major": float(lat_major),
        "latest_minor": float(lat_minor),
        "latest_patch": float(lat_patch),
        "latest_is_pre": 0.0,

        "is_latest": float(0 if latest_version and version != latest_version else 1),
        "gap_major": float(max(0, lat_major - ver_major)),
        "gap_minor": float(max(0, lat_minor - ver_minor)),
        "gap_patch": float(max(0, lat_patch - ver_patch)),
    }

    # date features
    now = pd.Timestamp.utcnow()
    crd = parse_date_safe(current_release_date)
    lrd = parse_date_safe(latest_release_date)
    row["age_days"]        = float((now - crd).days) if isinstance(crd, pd.Timestamp) else 0.0
    row["latest_age_days"] = float((now - lrd).days) if isinstance(lrd, pd.Timestamp) else 0.0
    row["staleness_days"]  = float((lrd - crd).days) if (isinstance(lrd, pd.Timestamp) and isinstance(crd, pd.Timestamp)) else 0.0

    return row, latest_version

def rows_from_csv(path):
    df = pd.read_csv(path)
    needed = ["ecosystem","package_name","version"]
    for c in needed:
        if c not in df.columns:
            raise SystemExit(f"Missing column '{c}' in {path}")
    return df[needed].to_dict(orient="records")

def rows_from_single(ecosystem, package, version):
    if not (ecosystem and package and version):
        raise SystemExit("Provide --ecosystem --package --version for single-mode, or use --input CSV.")
    return [{"ecosystem": ecosystem, "package_name": package, "version": version}]

def encode_rows(rows, latest_meta, assets):
    # Build feature blocks using saved encoders + numeric column list
    ohe_ecosys = assets["ohe_ecosys"]
    ohe_sev    = assets["ohe_sev"]
    hash_dims  = assets["hash_dims"]
    num_cols   = assets["num_cols"]

    # We will assemble sparse matrices piece by piece
    from sklearn.feature_extraction import FeatureHasher
    hasher = FeatureHasher(n_features=hash_dims, input_type="string")

    X_blocks = []
    pack = []  # carry per-row context (for rules)
    for r in rows:
        eco = str(r["ecosystem"])
        pkg = str(r["package_name"])
        ver = str(r["version"])

        meta_row = (latest_meta.get(eco, {}) or {}).get(pkg)
        # Unknown package → mark; still build a row for consistency but we will short-circuit to UNKNOWN
        unknown_pkg = meta_row is None

        row_dict, latest_version = build_single_row_df(eco, pkg, ver, meta_row)

        # categorical
        X_ecosys = ohe_ecosys.transform(pd.DataFrame([{"ecosystem": eco}]))
        X_sev    = ohe_sev.transform(pd.DataFrame([{"severity": row_dict["severity"]}]))

        # hashed pkg
        X_pkg = hasher.transform([[pkg]])

        # numeric block: ensure every expected column present
        num_row = [float(row_dict.get(c, 0.0)) for c in num_cols]
        X_num = sp.csr_matrix(np.array(num_row, dtype=float).reshape(1, -1))

        # final row
        X_row = sp.hstack([X_ecosys, X_sev, X_pkg, X_num], format="csr")
        X_blocks.append(X_row)

        pack.append({
            "ecosystem": eco,
            "package_name": pkg,
            "version": ver,
            "latest_version": latest_version,
            "unknown_pkg": unknown_pkg
        })

    X = sp.vstack(X_blocks, format="csr")
    return X, pack

def predict_with_rules(rows, latest_meta, assets):
    X, ctx = encode_rows(rows, latest_meta, assets)
    dmat = xgb.DMatrix(X)

    # model predicts probs → pick argmax (0=SAFE,1=OUTDATED,2=VULNERABLE)
    probs = assets["xgb_model"].predict(dmat)
    pred_ids = np.argmax(probs, axis=1)
    id2label = {v:k for k,v in assets["label_map"].items()}

    out = []
    for i, base_label_id in enumerate(pred_ids):
        base_label = id2label.get(int(base_label_id), "SAFE")
        row = ctx[i]
        eco, pkg, ver = row["ecosystem"], row["package_name"], row["version"]
        lat = row["latest_version"]

        # Rule 1: unknown package
        if row["unknown_pkg"]:
            out.append({
                "ecosystem": eco, "package_name": pkg, "version": ver,
                "model_prediction": base_label,
                "final_label": "UNKNOWN",
                "reason": "Package not found in metadata",
                "suggested_action": "Verify package name or add to metadata"
            })
            continue

        # Rule 2: smart version gap → OUTDATED
        if lat and smart_gap_is_outdated(ver, lat):
            out.append({
                "ecosystem": eco, "package_name": pkg, "version": ver,
                "latest_version": lat,
                "model_prediction": base_label,
                "final_label": "OUTDATED",
                "reason": f"Major/minor behind latest ({lat})",
                "suggested_action": f"Upgrade to {lat}"
            })
            continue

        # Else: keep model result
        out.append({
            "ecosystem": eco, "package_name": pkg, "version": ver,
            "latest_version": lat,
            "model_prediction": base_label,
            "final_label": base_label,
            "reason": "No rule override",
            "suggested_action": "No action" if base_label=="SAFE" else "Review advisory"
        })

    return out

# ---------- main ----------
def main():
    args = parse_args()

    # inputs
    if args.input:
        rows = rows_from_csv(args.input)
    else:
        rows = rows_from_single(args.ecosystem, args.package, args.version)

    latest_meta = load_latest_meta(args.meta)
    assets = load_train_assets(args.train_meta, args.preproc, args.model)

    results = predict_with_rules(rows, latest_meta, assets)

    # Non-blocking mode (P-C): always exit 0. Only write JSON.
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.utcnow().isoformat(), "items": results}, f, indent=2)
    print(f"Saved JSON report → {args.out}")

if __name__ == "__main__":
    main()
