#!/usr/bin/env python3
"""
run_osv_pipeline.py - the whole process in one command:

    1. download_osv.py        download the OSV PyPI database        -> <workdir>/osv_data/PyPI/*.json
    2. build_dataset_osv.py   fetch the fix commits + ordinary ones -> <workdir>/dataset_osv.jsonl
    3. train_model.py         cross-validate + train                -> <workdir>/model_osv.joblib

    python run_osv_pipeline.py                       # everything, into ./osv_run
    python run_osv_pipeline.py --max-repos 50        # a small trial run first
    python run_osv_pipeline.py --no-train            # stop after the dataset

It can be stopped and started again: step 1 is skipped when the records exist, step 2 continues
where it stopped, and step 3 recomputes features whenever the dataset changed.
Put this file in the project folder (next to train_model.py) and run it from there.
Your existing model.joblib is never touched.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run(script, *args):
    path = os.path.join(HERE, script)
    if not os.path.exists(path):
        sys.exit(f"missing {script} next to run_osv_pipeline.py")
    cmd = [sys.executable, path, *map(str, args)]
    print("\n$ " + " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode:
        sys.exit(f"step failed: {script} (exit code {r.returncode})")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", default="osv_run", help="folder for all outputs (default osv_run)")
    ap.add_argument("--max-repos", type=int, default=0, help="0 = all repos; use e.g. 50 for a trial run")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--depth", type=int, default=120)
    ap.add_argument("--max-pos-per-repo", type=int, default=12)
    ap.add_argument("--strict", action="store_true", help="only GIT-range / FIX-type commit links")
    ap.add_argument("--refresh", action="store_true", help="download OSV again (it is updated daily)")
    ap.add_argument("--zip", default=None, help="OSV zip you downloaded by hand")
    ap.add_argument("--no-train", action="store_true", help="stop after building the dataset")
    a = ap.parse_args()

    wd = os.path.abspath(a.workdir)
    os.makedirs(wd, exist_ok=True)
    osv_root, osv_dir = os.path.join(wd, "osv_data"), os.path.join(wd, "osv_data", "PyPI")
    dataset = os.path.join(wd, "dataset_osv.jsonl")
    cache = os.path.join(wd, "features_osv.pkl")
    model = os.path.join(wd, "model_osv.joblib")

    # 1. download
    args = ["--out-dir", osv_root]
    if a.refresh:
        args.append("--force")
    if a.zip:
        args += ["--zip", a.zip]
    run("download_osv.py", *args)

    # 2. dataset (resumable)
    args = ["--osv-dir", osv_dir, "--out", dataset, "--threads", a.threads, "--depth", a.depth,
            "--max-pos-per-repo", a.max_pos_per_repo, "--max-repos", a.max_repos,
            "--dump-fixes", os.path.join(wd, "fixes_osv.json")]
    if a.strict:
        args.append("--strict")
    run("build_dataset_osv.py", *args)
    if a.no_train:
        print(f"\ndataset ready: {dataset}")
        return
    if not os.path.exists(dataset):
        sys.exit("no dataset was produced - nothing to train on")

    # 3. train. train_model.load() trusts an existing cache blindly, so drop it if the dataset is newer
    if os.path.exists(cache) and os.path.getmtime(cache) < os.path.getmtime(dataset):
        os.remove(cache)
        print("dataset changed since the last run -> features will be recomputed")
    run("train_model.py", "--data", dataset, "--cache", cache, "--out", model)
    print(f"\nall done.\n  dataset: {dataset}\n  model  : {model}\n"
          f"  (your original model.joblib was not changed)")


if __name__ == "__main__":
    main()
