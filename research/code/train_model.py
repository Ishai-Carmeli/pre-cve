"""
train_model.py - train + honestly evaluate the silent-security-fix classifier.

    python train_model.py --data dataset.jsonl --out model.joblib

Evaluation = 5-fold GroupKFold BY REPOSITORY: the model is always tested on projects it
has never seen (otherwise it would just memorise project-specific vocabulary).
Reported: ROC-AUC, PR-AUC, recall at fixed false-positive rates, and the precision you
should expect in real life, where security commits are rare (prior given by --prior).
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import pickle
import sys
import warnings

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import MaxAbsScaler
from scipy.sparse import hstack

from features import LEGACY_FAMILIES, commit_features, filter_text

warnings.filterwarnings("ignore")


W_LR = 0.85      # weight of the text model in the final blend (chosen by cross-validation)


def _work(line):
    r = json.loads(line)
    try:
        text, struct = commit_features(r["files"])
    except Exception:
        text, struct = "", {}
    return r["sha"], r["repo"], r["label"], text, struct


def load(path, cache):
    """Stream the jsonl file, extract features in parallel, drop duplicate commits."""
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    seen, out = set(), []
    with open(path) as fh, mp.Pool(max(1, os.cpu_count())) as pool:
        for sha, repo, label, text, struct in pool.imap(_work, fh, chunksize=4):
            if sha in seen:
                continue
            seen.add(sha)
            out.append((repo, label, text, struct))
    data = {"y": np.array([o[1] for o in out]), "groups": np.array([o[0] for o in out]),
            "text": [o[2] for o in out], "struct": [o[3] for o in out]}
    pickle.dump(data, open(cache, "wb"))
    return data


def fit_models(text_tr, st_tr, y_tr):
    tf = TfidfVectorizer(token_pattern=r"\S+", lowercase=False, min_df=4, max_df=0.6, sublinear_tf=True,
                         max_features=200_000)
    dv = DictVectorizer()
    sc = MaxAbsScaler()
    Xt = tf.fit_transform(text_tr)
    Xs_raw = dv.fit_transform(st_tr)
    Xs = sc.fit_transform(Xs_raw)
    lr = LogisticRegression(C=2.0, class_weight="balanced", max_iter=3000, solver="liblinear")
    lr.fit(hstack([Xt, Xs]).tocsr(), y_tr)
    gb = HistGradientBoostingClassifier(max_depth=4, learning_rate=0.06, max_iter=250, l2_regularization=1.0,
                                        class_weight="balanced", random_state=0)
    gb.fit(Xs_raw.toarray(), y_tr)
    return {"tf": tf, "dv": dv, "sc": sc, "lr": lr, "gb": gb}


def predict(m, text, struct):
    Xt = m["tf"].transform(text)
    Xs_raw = m["dv"].transform(struct)
    p_lr = m["lr"].predict_proba(hstack([Xt, m["sc"].transform(Xs_raw)]).tocsr())[:, 1]
    p_gb = m["gb"].predict_proba(Xs_raw.toarray())[:, 1]
    return p_lr, p_gb, W_LR * p_lr + (1 - W_LR) * p_gb


def report(name, y, s, prior):
    auc, ap = roc_auc_score(y, s), average_precision_score(y, s)
    fpr, tpr, thr = roc_curve(y, s)
    row = [f"{name:<22} AUC={auc:.3f}  PR-AUC={ap:.3f}"]
    for target in (0.01, 0.05, 0.10):
        i = np.searchsorted(fpr, target, side="right") - 1
        t, f = tpr[i], max(fpr[i], 1e-9)
        prec = t * prior / (t * prior + f * (1 - prior))
        row.append(f"@FPR{int(target*100)}%: recall={t:.0%} prec@{prior:.0%}prior={prec:.0%}")
    print("  ".join(row))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="dataset.jsonl")
    ap.add_argument("--cache", default="features.pkl")
    ap.add_argument("--out", default="model.joblib")
    ap.add_argument("--prior", type=float, default=0.02, help="assumed share of security commits in real traffic")
    ap.add_argument("--families", default=",".join(LEGACY_FAMILIES),
                    help="feature families to train on (base,calls,ast,ctx,path); default = the best measured: base,path")
    a = ap.parse_args()
    fams = tuple(a.families.split(","))

    d = load(a.data, a.cache)
    d["text"] = [filter_text(t, fams) for t in d["text"]]
    y, groups = d["y"], d["groups"]
    print(f"{len(y)} commits ({int(y.sum())} security / {int((1-y).sum())} ordinary) from {len(set(groups))} repos")

    oof = {k: np.zeros(len(y)) for k in ("lr", "gb", "ens")}
    for k, (tr, te) in enumerate(GroupKFold(n_splits=5).split(np.zeros(len(y)), y, groups)):
        m = fit_models([d["text"][i] for i in tr], [d["struct"][i] for i in tr], y[tr])
        p_lr, p_gb, p = predict(m, [d["text"][i] for i in te], [d["struct"][i] for i in te])
        oof["lr"][te], oof["gb"][te], oof["ens"][te] = p_lr, p_gb, p
        print(f"  fold {k+1}: AUC ens = {roc_auc_score(y[te], p):.3f}", flush=True)

    baseline = np.array([s.get("rule_total", 0.0) for s in d["struct"]])
    print("\n=== repo-wise cross-validated results (unseen projects) ===")
    report("hand-written rules", y, baseline, a.prior)
    report("text model (LR)", y, oof["lr"], a.prior)
    report("structure model (GB)", y, oof["gb"], a.prior)
    report("ensemble", y, oof["ens"], a.prior)

    fpr, tpr, thr = roc_curve(y, oof["ens"])
    def thr_at(f):
        return float(thr[max(0, np.searchsorted(fpr, f, side="right") - 1)])
    ts = np.linspace(0.2, 0.95, 151)
    def f1_at(t):
        pred = oof["ens"] >= t
        tp = (pred & (y == 1)).sum(); fp = (pred & (y == 0)).sum(); fn = ((~pred) & (y == 1)).sum()
        return 2 * tp / max(1, 2 * tp + fp + fn)
    thresholds = {"flag": thr_at(0.02), "review": thr_at(0.10), "binary": float(max(ts, key=f1_at))}
    print("\nthresholds (from out-of-fold):", thresholds)
    print("\nthreshold   recall   false-alarm-rate   precision(on this mix)   precision if 2% are security")
    for t in (0.30, 0.40, thresholds["binary"], 0.55, 0.65, 0.80):
        pred = oof["ens"] >= t
        tp = (pred & (y == 1)).sum(); fp = (pred & (y == 0)).sum()
        rec, fpr_ = tp / y.sum(), fp / (y == 0).sum()
        print(f"{t:>8.3f}   {rec:>5.0%}    {fpr_:>8.0%}           {tp / max(1, tp + fp):>8.0%}"
              f"                {rec * .02 / (rec * .02 + fpr_ * .98):>8.0%}")

    m = fit_models(d["text"], d["struct"], y)
    import joblib
    joblib.dump({"models": m, "thresholds": thresholds, "n_train": int(len(y)), "prior": a.prior,
                 "families": fams}, a.out)
    print("saved", a.out)

    # most informative words, for sanity
    names = np.array(m["tf"].get_feature_names_out())
    w = m["lr"].coef_[0][:len(names)]
    top = np.argsort(w)
    print("\nwords pushing towards SECURITY :", ", ".join(names[top[-25:][::-1]]))
    print("words pushing towards ORDINARY :", ", ".join(names[top[:15]]))


if __name__ == "__main__":
    main()
