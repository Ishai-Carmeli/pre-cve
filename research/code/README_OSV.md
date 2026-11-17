# Training a new model from the OSV database (instead of pypa + GHSA)

Three new files. No existing file was changed, and the existing `model.joblib` is left untouched.

| File | What it does |
|---|---|
| `download_osv.py` | Downloads OSV's `PyPI/all.zip` and extracts it into JSON files (one record per file) |
| `build_dataset_osv.py` | The new dataset builder: reads the OSV records, pulls the code from GitHub, and builds `dataset_osv.jsonl` |
| `run_osv_pipeline.py` | Runs everything in sequence: download, dataset, training (the existing `train_model.py`) |

## Setup (once)
1. Put the three files **in the same folder** as `train_model.py` and `commit_analyzer.py`. They import the file filters from there, so that training and usage filter exactly the same files.
2. Run `pip install -r requirements.txt` and make sure `git` is installed. The new files themselves use only the standard library.
3. You need network access to `storage.googleapis.com` and `github.com`.

## Running
```
python run_osv_pipeline.py --max-repos 50     # small trial first (minutes)
python run_osv_pipeline.py                    # everything (hours; can be stopped and resumed)
```
The outputs go in the `osv_run/` folder:
- `osv_data/PyPI/*.json`: the OSV records
- `dataset_osv.jsonl`: the dataset
- `fixes_osv.json`: the list of fix commits found (`{repo: {sha: id}}`)
- `features_osv.pkl`: the feature cache
- `model_osv.joblib`: **the new model**

You can also run it step by step:
```
python download_osv.py --out-dir osv_data
python build_dataset_osv.py --osv-dir osv_data/PyPI --dry-run     # statistics only, no git
python build_dataset_osv.py --osv-dir osv_data/PyPI --out dataset_osv.jsonl
python train_model.py --data dataset_osv.jsonl --cache features_osv.pkl --out model_osv.joblib
```
**Important:** in the training step, always pass `--cache` with a new name. `train_model.py` loads an existing cache without checking whether the dataset has changed (`run_osv_pipeline.py` deletes an old cache automatically).

## If the download fails
Open `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` in a browser, save the file, and run:
`python run_osv_pipeline.py --zip all.zip`

## How the dataset is built
1. Read every PyPI OSV record that has not been withdrawn (`withdrawn`).
2. Fix commits are taken from three places, recorded in the `evidence` field:
   - `git_range`: a GIT-type range with `fixed` (the most reliable)
   - `fix_ref`: a FIX-type link to a commit
   - `web_ref`: any other link to a commit (noisier; `--strict` leaves these out)
3. A commit that appears in several records (PYSEC + GHSA and others) becomes a single entry.
4. For each repo: pull only the commits needed, extract the code before and after (label 1), and for each fix add 2 random commits from the history before the first fix (label 0, **not verified**, as in the original process).
5. You can stop (Ctrl-C) and run again: finished repos are recorded in `dataset_osv.jsonl.done`.

New fields in each entry (training ignores them): `published` (the first publication date), `commit_date`, `vulns`, `evidence`. The difference `published` minus `commit_date` is the fix's lead time.

## Useful options
`--strict` reliable links only · `--max-repos N` / `--offset N` a partial or separate subset · `--max-pos-per-repo` (12) · `--neg-per-pos` (2) · `--threads` (8) · `--depth` (120) · `--refresh` download again (OSV updates daily)

## Known limitations
- The "ordinary" commits are not verified, and some may be silent fixes.
- A record with no commit link can't be used, and a link with a short sha that can't be completed is discarded (the statistics are printed at the start of the run).
- Repos that were deleted or made private are skipped. Results vary slightly between runs because OSV and GitHub change.
- To use the new model on the website or in `check_package.py`, copy `model_osv.joblib` to `model.joblib` (keep a backup of the existing one); the path is hard-coded.

## What was tested and what wasn't
Tested: the download and extraction (from a local zip file), the commit extraction, and building a dataset on real GitHub repos (14 repos, including resuming a run). Not tested: the real OSV URL (blocked in the environment where testing was done) and the training step inside `run_osv_pipeline.py`. Training itself is the existing `train_model.py`, and the flags used do exist in it.
