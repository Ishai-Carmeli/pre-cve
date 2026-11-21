# PreCVE

Detect **silent security fixes** in PyPI packages: commits that fix a vulnerability before any advisory (CVE / GHSA) is published.

BGU final project — Ishai Carmeli, Tamir Dalva.

## Status

The first stage is done: building a labeled dataset of fix commits from the [OSV](https://osv.dev) database.

| Step | Script | Output |
|---|---|---|
| 1. Download OSV PyPI records | `download_osv.py` | `osv_data/PyPI/*.json` |
| 2. Build the dataset | `build_dataset_osv.py` | `dataset_osv.jsonl` + `dataset_osv.log` |
| 3. Train | `train_model.py` | not run on the OSV data yet |

**Last full run:**

| | Count |
|---|---:|
| Repos with fix commits | 1,107 |
| Unique fix commits found in OSV | 5,319 |
| Dataset rows, fixes (label 1) | 2,460 |
| Dataset rows, ordinary commits (label 0) | 4,904 |

Each row is one commit: the message, the before/after code of up to 15 changed code files, the commit dates, and for fixes the advisory IDs, `published` date and link evidence (`git_range` / `fix_ref` / `web_ref`).

**Also done:**
- Type hints throughout `build_dataset_osv.py`; data shapes are named in `dataset_types.py`
- Everything printed is also saved to a log file (`my_logger.py`; turn off with `--no-log`)
- Dependency versions pinned in `requirements-lock.txt`

## Run

From `research/code/`:

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-lock.txt

python download_osv.py
python build_dataset_osv.py --osv-dir osv_data/PyPI --dry-run     # statistics only
python build_dataset_osv.py --osv-dir osv_data/PyPI               # full run (hours; Ctrl-C and rerun to resume)
```

## Known issues

Tracked in `research/code/Notes.MD`. The main ones:
- **Negatives may contain fixes.** A fix later in the loop can be picked as an ordinary commit from the history before the first fix.
- **Near-duplicates.** Backports (cherry-picks) of one fix appear as separate rows, so train/test must be split by repo.
- **Dates.** `commit_date` is not when the fix landed on main, so lead time (`published − commit_date`) is approximate.
- **Filters.** Code files named `news.py`, `changes.py`, `license.py`, … are dropped as documentation.

Open question: whether to train on this dataset or on PySecDB (hand-verified labels).

## Layout

```
research/
  code/              scripts, notes (Notes.MD), README_OSV.md (dataset pipeline details)
  claude-context/    PRD draft and background research
  Tasks.md           current tasks
```
