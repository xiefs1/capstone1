#!/usr/bin/env python3
import sys
import json
import joblib
import requests
import pandas as pd

# ---------------------- VERSION PARSER ----------------------
def parse_version(v):
    try:
        parts = str(v).split(".")
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return major, minor, patch
    except:
        return 0, 0, 0


def compare_versions(v1, v2):
    """Return -1 if v1<v2, 0 if equal, 1 if v1>v2."""
    a1, b1, c1 = parse_version(v1)
    a2, b2, c2 = parse_version(v2)
    if (a1, b1, c1) < (a2, b2, c2):
        return -1
    if (a1, b1, c1) > (a2, b2, c2):
        return 1
    return 0


# ---------------------- ECOSYSTEM DETECTION ----------------------
def detect_ecosystem(pkg):
    p = pkg.lower()
    # quick hints, you can add more if you want
    npm_names = {"express", "lodash", "axios"}
    pypi_names = {"requests", "flask", "django", "urllib3", "pillow", "numpy", "pandas"}
    ruby_names = {"rails", "sinatra", "rake", "jekyll"}

    if p in npm_names:
        return "npm"
    if p in pypi_names:
        return "PyPI"
    if p in ruby_names:
        return "RubyGems"

    # fallback guess: PyPI
    return "PyPI"


# ---------------------- LATEST VERSION (REGISTRIES) ----------------------
def get_latest_version(package, ecosystem):
    eco = ecosystem.lower()
    try:
        if eco == "pypi":
            url = f"https://pypi.org/pypi/{package}/json"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                return r.json()["info"]["version"]

        if eco == "npm":
            url = f"https://registry.npmjs.org/{package}"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                latest = data.get("dist-tags", {}).get("latest")
                if latest:
                    return latest

        if eco == "rubygems":
            url = f"https://rubygems.org/api/v1/versions/{package}/latest.json"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                return r.json().get("version")

    except Exception:
        return None

    return None


# ---------------------- OSV CHECK (RULE: VULNERABLE?) ----------------------
def is_vulnerable_osv(package, ecosystem, version):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }
    try:
        r = requests.post(url, json=payload, timeout=20)
        if r.status_code != 200:
            return False, None, None
        data = r.json()
        vulns = data.get("vulns") or []
        if not vulns:
            return False, None, None
        # just take first vuln as representative
        v = vulns[0]
        vid = v.get("id")
        severity = None
        if v.get("severity"):
            try:
                severity = float(v["severity"][0].get("score"))
            except Exception:
                severity = None
        return True, vid, severity
    except Exception:
        return False, None, None


# ---------------------- FEATURE ENGINEERING (MATCH TRAINING) ----------------------
def build_features_for_ml(df):
    df = df.copy()

    # version features
    df["current_major"], df["current_minor"], df["current_patch"] = zip(
        *df["current_version"].apply(parse_version)
    )
    df["latest_major"], df["latest_minor"], df["latest_patch"] = zip(
        *df["latest_version"].apply(parse_version)
    )

    df["version_gap_major"] = df["latest_major"] - df["current_major"]
    df["version_gap_minor"] = df["latest_minor"] - df["current_minor"]
    df["version_gap_patch"] = df["latest_patch"] - df["current_patch"]

    df["is_latest"] = (df["current_version"] == df["latest_version"]).astype(int)

    # cvss score + vuln flag already set upstream
    df["cvss_score_f"] = df["cvss_score_f"].astype(float)
    df["has_vuln_id"] = df["has_vuln_id"].astype(int)

    return df


# ---------------------- PARSE requirements lines ----------------------
def parse_req_line(line):
    if "==" not in line:
        return None, None
    pkg, ver = line.strip().split("==", 1)
    return pkg.strip(), ver.strip()


# ---------------------- MAIN ----------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python sca_inference_with_rules.py <requirements.txt>")
        return

    input_file = sys.argv[1]

    try:
        with open(input_file, "r") as f:
            lines = f.readlines()
    except Exception:
        print(f"ERROR: cannot read {input_file}")
        return

    # Try to load ML model (optional)
    try:
        ml_model = joblib.load("sca_model.pkl")
        ml_le = joblib.load("sca_label_encoder.pkl")
        use_ml = True
        print("Loaded ML model for hybrid predictions.")
    except Exception:
        ml_model = None
        ml_le = None
        use_ml = False
        print("WARNING: ML model not found, using rules only.")

    rows = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "package_name" in line:
            # skip header or comments
            continue

        pkg, ver = parse_req_line(line)
        if not pkg:
            print(f"Skipping invalid line: {line}")
            continue

        eco = detect_ecosystem(pkg)
        latest = get_latest_version(pkg, eco)
        if not latest:
            latest = ver  # fallback

        vuln, vuln_id, cvss = is_vulnerable_osv(pkg, eco, ver)

        # rule-based label
        if vuln:
            rule_label = "VULNERABLE"
        else:
            cmp = compare_versions(ver, latest)
            if cmp < 0:
                rule_label = "OUTDATED"
            else:
                rule_label = "SAFE"

        rows.append({
            "ecosystem": eco,
            "package_name": pkg,
            "current_version": ver,
            "latest_version": latest,
            "rule_label": rule_label,
            "has_vuln_id": 1 if vuln else 0,
            "cvss_score_f": cvss if cvss is not None else 0.0,
            "osv_vuln_id": vuln_id
        })

    if not rows:
        print("No valid dependencies found.")
        return

    df = pd.DataFrame(rows)

    # ---------- ML PART (optional) ----------
    if use_ml:
        feat_df = build_features_for_ml(df)
        X = feat_df[[
            "current_major", "current_minor", "current_patch",
            "latest_major", "latest_minor", "latest_patch",
            "version_gap_major", "version_gap_minor", "version_gap_patch",
            "is_latest", "cvss_score_f", "has_vuln_id",
            "ecosystem", "package_name"
        ]]
        preds = ml_model.predict(X)
        probs = ml_model.predict_proba(X)

        ml_labels = [ml_le.inverse_transform([p])[0] for p in preds]
        ml_conf = [float(max(p_row)) for p_row in probs]
    else:
        ml_labels = ["N/A"] * len(df)
        ml_conf = [0.0] * len(df)

    # ---------- FINAL RESULTS ----------
    results = []
    for i, row in df.iterrows():
        results.append({
            "package": row["package_name"],
            "version": row["current_version"],
            "ecosystem": row["ecosystem"],
            "rule_label": row["rule_label"],
            "osv_vuln_id": row["osv_vuln_id"],
            "ml_label": ml_labels[i],
            "ml_confidence": round(ml_conf[i], 5),
        })

    with open("sca_report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print("\n=== HYBRID SCA RESULTS (rules + ML) ===")
    print(json.dumps(results, indent=4))
    print("\nSaved → sca_report.json")


if __name__ == "__main__":
    main()
