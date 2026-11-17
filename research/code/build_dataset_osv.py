#!/usr/bin/env python3
"""
build_dataset_osv.py - build the training dataset from the OSV database
(the replacement for build_dataset.py, which reads the PyPA YAML files / a GHSA json).

Input : a folder of OSV records (*.json, one vulnerability each) - see download_osv.py
Output: a .jsonl file, one commit per line, in the SAME format train_model.py already reads:
        {"repo","sha","label","vuln","message","files":[{"path","status","before","after"}]}
        plus extra fields that the training ignores but that you can use for analysis:
        "vulns" (all advisory ids), "published" (earliest advisory date), "evidence",
        "commit_date", "author_date"  -> "published" minus "commit_date" = how early a fix existed
        before it was announced (the lead time the project is about).

How it works
  1. Read every OSV record; keep PyPI ones that are not withdrawn and are not "MAL-" records
     (malicious packages: nothing was "fixed", so they are no examples of a fix).
  2. Collect fix commits per GitHub repo from
       - ranges of type GIT with a "fixed" commit           (evidence "git_range", most reliable)
       - references of type FIX that point to a commit      (evidence "fix_ref")
       - any other reference that points to a commit        (evidence "web_ref", noisier; off with --strict)
       - references of type INTRODUCED are NEVER used (they point to the commit that CREATED the bug)
     The same commit listed by several advisories (PYSEC + GHSA + ...) becomes ONE entry.
  3. For each repo (in parallel threads): fetch only the needed commits from GitHub, extract the code
     before/after every fix (label 1) and a few random earlier commits of the same repo (label 0,
     "ordinary" = unverified, exactly as in the original pipeline), and append them to the output.
  Safe to stop (Ctrl-C) and run again: finished repos are remembered in <out>.done and skipped.

Run it from the project folder (it imports the file filters from commit_analyzer.py, so training and
use filter exactly the same files):

    python build_dataset_osv.py --osv-dir osv_data/PyPI --out dataset_osv.jsonl
    python build_dataset_osv.py --osv-dir osv_data/PyPI --dry-run        # statistics only, no git
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from commit_analyzer import CODE_EXT, _DOC_RE, _TEST_RE, _VENDOR_RE
except ImportError as e:                                             # pragma: no cover
    sys.exit(f"cannot import commit_analyzer ({e}).\nPut this file in the project folder (next to "
             f"commit_analyzer.py) and run it from there; install requirements.txt first.")

ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true")   # never wait for a password
MAX_FILE = 120_000          # skip files bigger than this many characters
MAX_FILES = 15              # keep at most this many files (largest change first) per commit
LOCK = threading.Lock()

_REPO_URL = re.compile(r"https?://(?:www\.)?github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?/?$")
_COMMIT_URL = re.compile(r"https?://(?:www\.)?github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?/"
                         r"(?:commit/|pull/\d+/commits/)([0-9a-fA-F]{7,40})(?![0-9A-Za-z])")
_HEX = re.compile(r"^[0-9a-f]{7,40}$")
_ANY_REPO = re.compile(r"https?://(?:www\.)?github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?(?:[/#?].*)?$", re.I)
_GONE = re.compile(r"not found|could not read Username|Authentication failed|access denied|"
                   r"Repository unavailable|DMCA|disabled", re.I)
_TRANSIENT = re.compile(r"timed out|timeout|unable to access|Connection|reset|RPC failed|early EOF|"
                        r"HTTP/2|\b50[0234]\b|\b429\b|rate limit", re.I)


# --------------------------------------------------------------------------- git helpers
def sh(cwd, *args, timeout=240):
    p = subprocess.run(["git", "-C", cwd, *args], capture_output=True, timeout=timeout, env=ENV)
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf-8", "replace")[:300])
    return p.stdout.decode("utf-8", "replace")


def fetch(cwd, sha, depth, tries=3):
    """git fetch of one commit, with a few retries for network hiccups."""
    for i in range(tries):
        try:
            return sh(cwd, "fetch", "-q", f"--depth={depth}", "origin", sha, timeout=300)
        except subprocess.TimeoutExpired:
            if i == tries - 1:
                raise
        except RuntimeError as e:
            if i == tries - 1 or not _TRANSIENT.search(str(e)):
                raise
        time.sleep(2 * (i + 1))


# --------------------------------------------------------------------------- OSV -> fix commits
def is_pypi(rec) -> bool:
    return any(str((a.get("package") or {}).get("ecosystem", "")).split(":")[0] == "PyPI"
               for a in rec.get("affected") or [])


def extract_fixes(rec, strict=False, stats=None):
    """-> [(repo 'owner/name' lowercase, commit sha lowercase, evidence)] found in one OSV record.
    `stats` (a Counter, optional) counts the INTRODUCED links that were ignored."""
    out = []
    for a in rec.get("affected") or []:
        for rg in a.get("ranges") or []:
            if rg.get("type") == "GIT" and rg.get("repo"):
                m = _REPO_URL.match(str(rg["repo"]).strip())
                if not m:
                    continue
                for e in rg.get("events") or []:
                    fx = str(e.get("fixed", "")).strip().lower()
                    if _HEX.match(fx):
                        out.append((m.group(1).lower(), fx, "git_range"))
    for ref in rec.get("references") or []:
        if not isinstance(ref, dict):
            continue
        m = _COMMIT_URL.match(str(ref.get("url", "")).strip())
        if not m:
            continue
        if ref.get("type") == "INTRODUCED":          # the commit that created the bug, never the fix
            if stats is not None:
                stats["introduced_ref_skipped"] += 1
            continue
        ev = "fix_ref" if ref.get("type") == "FIX" else "web_ref"
        if strict and ev == "web_ref":
            continue
        out.append((m.group(1).lower(), m.group(2).lower(), ev))
    return out


def repos_in(rec):
    """lower-case owner/name of every GitHub repo mentioned in a record (reference links + GIT ranges)."""
    urls = [str(r.get("url", "")) for r in rec.get("references") or [] if isinstance(r, dict)]
    urls += [str(rg.get("repo", "")) for a in rec.get("affected") or [] for rg in a.get("ranges") or []
             if isinstance(rg, dict)]
    return {m.group(1).lower() for u in urls for m in [_ANY_REPO.match(u.strip())] if m}


def collect_fixes(osv_dir, strict=False, any_ecosystem=False, mal=None):
    """Read every record -> ({repo: {sha: {"ids": set, "published": str, "evidence": set}}}, Counter).
    `mal` (optional dict) is filled with sets measured on the records themselves: "repos" (GitHub repos
    mentioned by MAL records), "commit_repos" (those with a commit link) and "other_repos" (repos
    mentioned by any non-MAL record)."""
    fixes, st = {}, Counter()
    for root, _, files in os.walk(osv_dir):
        for fn in sorted(files):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(root, fn), encoding="utf-8") as fh:
                    rec = json.load(fh)
            except (OSError, ValueError):
                st["unreadable_files"] += 1
                continue
            if not isinstance(rec, dict) or "id" not in rec:
                st["not_an_osv_record"] += 1
                continue
            st["records"] += 1
            if rec.get("withdrawn"):
                st["withdrawn_skipped"] += 1
                continue
            st["prefix_" + (str(rec["id"]).split("-")[0] or "?")] += 1
            if str(rec["id"]).startswith("MAL-"):      # malicious package: no fix commit to learn from
                st["mal_skipped"] += 1
                if mal is not None:
                    rp = repos_in(rec)
                    mal["repos"] |= rp
                    st["mal_with_repo"] += bool(rp)
                    if extract_fixes(rec):                  # it WOULD have been taken as a fix commit
                        st["mal_with_commit_link"] += 1
                        mal["commit_repos"] |= rp
                continue
            if mal is not None:
                mal["other_repos"] |= repos_in(rec)
            if not any_ecosystem and not is_pypi(rec):
                st["non_pypi_skipped"] += 1
                continue
            found = extract_fixes(rec, strict, st)
            if not found:
                st["records_without_commit"] += 1
                continue
            st["records_with_commit"] += 1
            for repo, sha, ev in found:
                d = fixes.setdefault(repo, {}).setdefault(sha, {"ids": set(), "published": "", "evidence": set()})
                d["ids"].add(str(rec["id"]))
                d["evidence"].add(ev)
                pub = str(rec.get("published") or "")
                if pub and (not d["published"] or pub < d["published"]):
                    d["published"] = pub
    # a short sha (7-39 chars) cannot be fetched from GitHub: merge it into the matching full sha, else drop it
    for repo in list(fixes):
        shas = fixes[repo]
        fulls = [s for s in shas if len(s) == 40]
        for s in [s for s in shas if len(s) < 40]:
            info = shas.pop(s)
            cand = [f for f in fulls if f.startswith(s)]
            if len(cand) == 1:
                t = shas[cand[0]]
                t["ids"] |= info["ids"]
                t["evidence"] |= info["evidence"]
                if info["published"] and (not t["published"] or info["published"] < t["published"]):
                    t["published"] = info["published"]
                st["short_sha_merged"] += 1
            else:
                st["short_sha_dropped"] += 1
        if not shas:
            del fixes[repo]
    return fixes, st


def count_evidence(fixes):
    """Count each fix commit once, by its strongest evidence: git_range, else fix_ref, else web_ref.
    The three counts never overlap and add up to the number of unique fix commits."""
    counts = Counter()
    for shas in fixes.values():
        for d in shas.values():
            if "git_range" in d["evidence"]:
                counts["git_range"] += 1
            elif "fix_ref" in d["evidence"]:
                counts["fix_ref"] += 1
            else:
                counts["web_ref"] += 1
    return counts


def primary_id(ids):
    return sorted(ids, key=lambda i: (not i.startswith(("PYSEC", "GHSA")), i))[0]


# --------------------------------------------------------------------------- one commit -> one record
def record(cwd, sha, label, repo, info=None):
    """Extract one commit into a dict, or None if it is unusable (merge commit, no code files, ...)."""
    parents = sh(cwd, "rev-list", "--parents", "-n", "1", sha).split()[1:]
    if len(parents) != 1:
        return None
    parent = parents[0]
    try:
        sh(cwd, "cat-file", "-e", parent + "^{commit}")
    except RuntimeError:
        return None
    msg = sh(cwd, "log", "-1", "--format=%B", sha)
    dates = sh(cwd, "log", "-1", "--format=%cI%n%aI", sha).split()
    files = []
    listing = sh(cwd, "-c", "core.quotepath=false", "diff-tree", "--no-commit-id", "--name-status", "-r", "-M", sha)
    for line in listing.splitlines():
        parts = line.split("\t")
        st = parts[0][:1]
        if st not in ("M", "A", "R") or len(parts) < 2:
            continue
        old, new = (parts[1], parts[2]) if st == "R" else (parts[1], parts[1])
        if (not new.lower().endswith(CODE_EXT) or _TEST_RE.search(new)
                or _DOC_RE.search(new) or _VENDOR_RE.search(new)):
            continue
        try:
            after = sh(cwd, "show", f"{sha}:{new}")
            before = "" if st == "A" else sh(cwd, "show", f"{parent}:{old}")
        except RuntimeError:
            continue
        if len(after) > MAX_FILE or len(before) > MAX_FILE:
            continue
        files.append({"path": new, "status": st, "before": before, "after": after})
    if not files:
        return None
    files.sort(key=lambda f: -abs(len(f["after"]) - len(f["before"])))
    rec = {"repo": repo, "sha": sha, "label": label, "vuln": None, "message": msg, "files": files[:MAX_FILES],
           "commit_date": dates[0] if dates else None, "author_date": dates[1] if len(dates) > 1 else None}
    if info:
        rec.update({"vuln": primary_id(info["ids"]), "vulns": sorted(info["ids"]),
                    "published": info["published"] or None, "evidence": sorted(info["evidence"])})
    return rec


# --------------------------------------------------------------------------- one repo
def work_repo(repo, shas, neg_per_pos, out_path, done_path, depth):
    """Fetch one repo's fix commits (label 1) + random earlier commits (label 0); append to out_path."""
    tmp = tempfile.mkdtemp(prefix="osv_ds_")
    got = Counter()
    try:
        sh(tmp, "init", "-q")
        sh(tmp, "remote", "add", "origin", f"https://github.com/{repo}")
        recs, negs, pos_full, have_history = [], [], set(), False
        for sha, info in shas.items():
            try:
                # only the first fix is fetched with real history; every later "fetch --depth" re-cuts the
                # shallow boundary and would remove that history, so the ordinary commits are taken right now
                fetch(tmp, sha, 2 if have_history else depth)
                full = sh(tmp, "rev-parse", sha + "^{commit}").strip()
            except Exception as e:
                got["fix_fetch_failed"] += 1
                if not have_history and _GONE.search(str(e)):
                    got["repo_unavailable"] += 1          # deleted / private repo: do not try the other fixes
                    break
                continue
            if full in pos_full:
                continue
            pos_full.add(full)
            try:
                r = record(tmp, full, 1, repo, info)
            except Exception:
                r = None
            if not r:
                got["fix_unusable"] += 1
                continue
            recs.append(r)
            got["pos"] += 1
            if not have_history:
                have_history = True
                # ordinary commits: random earlier commits from the history before this (first) fix
                try:
                    hist = sh(tmp, "rev-list", "--no-merges", "-n", str(depth), full + "^").split()
                except Exception:
                    hist = []
                random.Random(full).shuffle(hist)
                want = neg_per_pos * len(shas)
                for h in hist:
                    if len(negs) >= want:
                        break
                    if h in pos_full:
                        continue
                    try:
                        r = record(tmp, h, 0, repo)
                    except Exception:
                        r = None
                    if r:
                        negs.append(r)
        negs = negs[:neg_per_pos * got["pos"]]          # keep the ratio if some fixes could not be used
        got["neg"] = len(negs)
        with LOCK:
            with open(out_path, "a", encoding="utf-8") as fh:
                for r in recs + negs:
                    fh.write(json.dumps(r) + "\n")
            with open(done_path, "a", encoding="utf-8") as fh:
                fh.write(repo + "\n")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return repo, got


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--osv-dir", required=True, help="folder with OSV *.json records (download_osv.py output)")
    ap.add_argument("--out", default="dataset_osv.jsonl")
    ap.add_argument("--max-repos", type=int, default=0, help="0 = all repos (default); otherwise process this many")
    ap.add_argument("--offset", type=int, default=0, help="skip the first N repos (e.g. for a disjoint hold-out set)")
    ap.add_argument("--max-pos-per-repo", type=int, default=12, help="at most N fix commits per repo")
    ap.add_argument("--neg-per-pos", type=int, default=2, help="ordinary commits per fix commit")
    ap.add_argument("--depth", type=int, default=120, help="history depth fetched around the first fix")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--skip", default="tensorflow/tensorflow,pytorch/pytorch", help="comma list of huge repos to skip")
    ap.add_argument("--strict", action="store_true",
                    help="only trust GIT ranges and FIX-type references (drop generic web links to commits)")
    ap.add_argument("--any-ecosystem", action="store_true", help="do not require the record to be a PyPI package")
    ap.add_argument("--seed", type=int, default=1, help="seed of the repo shuffle")
    ap.add_argument("--dump-fixes", default=None, help="also write {repo: {sha: id}} as json (old --fixes-json format)")
    ap.add_argument("--dry-run", action="store_true", help="print statistics and stop (no git, no output file)")
    a = ap.parse_args()

    if not os.path.isdir(a.osv_dir):
        sys.exit(f"{a.osv_dir} is not a folder - run download_osv.py first")
    mal = {"repos": set(), "commit_repos": set(), "other_repos": set()}
    fixes, st = collect_fixes(a.osv_dir, a.strict, a.any_ecosystem, mal)
    if not fixes:
        sys.exit("no fix commits found in the OSV records (check --osv-dir)")
    ev = count_evidence(fixes)
    n_commits = sum(len(v) for v in fixes.values())
    print("OSV records read            :", st["records"])
    print("  withdrawn (skipped)       :", st["withdrawn_skipped"])
    live = st["records"] - st["withdrawn_skipped"]
    print("  MAL malicious (skipped)   :", st["mal_skipped"], f"({st['mal_skipped'] / max(1, live):.1%} of the {live} live records)")
    print("      mentioning a repo     :", st["mal_with_repo"], f"({len(mal['repos'])} distinct GitHub repos)")
    print("      with a commit link    :", st["mal_with_commit_link"], f"({len(mal['commit_repos'])} repos)"
          " - would have been taken as fixes without the MAL filter")
    print("      repos also in non-MAL :", len(mal["repos"] & mal["other_repos"]), "(repos that MAL and a real advisory both mention)")
    print("  not PyPI (skipped)        :", st["non_pypi_skipped"])
    print("  with a fix-commit link    :", st["records_with_commit"])
    print("  without any commit link   :", st["records_without_commit"], "(cannot be used)")
    print("INTRODUCED links ignored    :", st["introduced_ref_skipped"])
    print("records by id prefix        :", {k[7:]: v for k, v in sorted(st.items()) if k.startswith("prefix_")})
    print("short shas merged / dropped :", st["short_sha_merged"], "/", st["short_sha_dropped"])
    print(f"=> {len(fixes)} repos, {n_commits} unique fix commits   (evidence: {dict(ev)})")
    if a.dump_fixes:
        with open(a.dump_fixes, "w") as fh:
            json.dump({r: {s: primary_id(d["ids"]) for s, d in v.items()} for r, v in fixes.items()}, fh)
        print("fixes written to", a.dump_fixes)
    if a.dry_run:
        return

    skip = {s.strip().lower() for s in a.skip.split(",") if s.strip()}
    repos = sorted(r for r in fixes if r not in skip)
    random.Random(a.seed).shuffle(repos)
    repos = repos[a.offset:(a.offset + a.max_repos) if a.max_repos else None]
    done_path = a.out + ".done"
    done = set()
    for p in (done_path,):
        if os.path.exists(p):
            done |= {l.strip() for l in open(p, encoding="utf-8") if l.strip()}
    todo = [r for r in repos if r not in done]
    print(f"processing {len(todo)} repos (already done: {len(repos) - len(todo)}) with {a.threads} threads "
          f"-> {a.out}", flush=True)

    total, n = Counter(), 0
    ex = ThreadPoolExecutor(a.threads)
    try:
        futs = {}
        for r in todo:
            order = sorted(fixes[r].items(), key=lambda kv: (kv[1]["published"] or "9999", kv[0]))
            futs[ex.submit(work_repo, r, dict(order[:a.max_pos_per_repo]), a.neg_per_pos, a.out, done_path,
                           a.depth)] = r
        for f in as_completed(futs):
            n += 1
            try:
                repo, got = f.result()
                total.update(got)
                print(f"[{n}/{len(todo)}] {repo} +{got['pos']} -{got['neg']}"
                      + (" (repo unavailable)" if got["repo_unavailable"] else ""), flush=True)
            except Exception as e:
                total["repo_crashed"] += 1
                print(f"[{n}/{len(todo)}] {futs[f]} FAILED {str(e)[:100]}", flush=True)
    except KeyboardInterrupt:
        print("\ninterrupted - finished repos are saved; run the same command again to continue", flush=True)
        ex.shutdown(wait=False, cancel_futures=True)
        sys.exit(130)
    ex.shutdown()
    print(f"\ndone. this run: {total['pos']} fix commits (label 1), {total['neg']} ordinary commits (label 0)")
    print(f"      fix commits that could not be fetched: {total['fix_fetch_failed']}, "
          f"unusable (no code files/merge): {total['fix_unusable']}, "
          f"repos gone/private: {total['repo_unavailable']}, crashed: {total['repo_crashed']}")
    print(f"next: python train_model.py --data {a.out} --cache features_osv.pkl --out model_osv.joblib")


if __name__ == "__main__":
    main()
