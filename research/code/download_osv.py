#!/usr/bin/env python3
"""
download_osv.py - download the public OSV vulnerability database for one ecosystem (default: PyPI)
and unpack it into plain JSON files, one file per vulnerability.

    python download_osv.py                      # -> osv_data/PyPI/*.json
    python download_osv.py --out-dir my_osv     # -> my_osv/PyPI/*.json
    python download_osv.py --force              # download again (OSV is updated every day)
    python download_osv.py --zip all.zip        # you already downloaded the zip by hand

Source: https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip  (public, no key, no payment).
The OSV database already merges the PyPA advisory database, the GitHub advisory database and others,
so one download replaces both sources used by build_dataset.py.

Only the Python standard library is needed.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
import zipfile

URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"


def _mb(n: int) -> str:
    return f"{n / 1e6:,.1f} MB"


def fetch_zip(url: str, dest: str, retries: int = 3) -> None:
    """Download `url` to `dest` (through a .part file, so a broken download never looks complete)."""
    part = dest + ".part"
    last = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "precve-osv-downloader/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as f:
                total = int(r.headers.get("Content-Length") or 0)
                got, tick = 0, time.time()
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
                    got += len(chunk)
                    if time.time() - tick > 2:
                        pct = f" ({got * 100 // total}%)" if total else ""
                        print(f"  downloaded {_mb(got)}{pct}", end="\r", flush=True)
                        tick = time.time()
            if total and got != total:
                raise OSError(f"incomplete download ({got} of {total} bytes)")
            os.replace(part, dest)
            print(f"  downloaded {_mb(os.path.getsize(dest))}          ")
            return
        except urllib.error.HTTPError as e:
            last = e
            print(f"attempt {attempt}/{retries} failed: HTTP {e.code} {e.reason}", file=sys.stderr)
            if e.code in (401, 403, 404):          # retrying will not help
                break
        except (urllib.error.URLError, OSError) as e:
            last = e
            print(f"attempt {attempt}/{retries} failed: {e}", file=sys.stderr)
        time.sleep(3 * attempt)
    if os.path.exists(part):
        os.remove(part)
    sys.exit(f"\ncould not download {url}\n  last error: {last}\n"
             f"  manual fallback: open that URL in a browser, save the file, then run again with --zip <file>")


def extract(zip_path: str, out_dir: str) -> int:
    """Extract every .json member into `out_dir` (flat; only the base name is used, so a hostile
    zip cannot write outside the folder). Returns the number of records."""
    os.makedirs(out_dir, exist_ok=True)
    n = 0
    with zipfile.ZipFile(zip_path) as z:
        bad = z.testzip()
        if bad:
            sys.exit(f"the zip file is corrupt (first bad member: {bad}); delete it and download again")
        for info in z.infolist():
            name = os.path.basename(info.filename)
            if info.is_dir() or not name.endswith(".json"):
                continue
            with z.open(info) as src, open(os.path.join(out_dir, name), "wb") as dst:
                shutil.copyfileobj(src, dst)
            n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ecosystem", default="PyPI", help="OSV ecosystem name (default PyPI)")
    ap.add_argument("--out-dir", default="osv_data", help="parent folder (records go to <out-dir>/<ecosystem>/)")
    ap.add_argument("--url", default=None, help="override the download URL (mirror, or file:///... for tests)")
    ap.add_argument("--zip", default=None, help="use this already-downloaded zip instead of downloading")
    ap.add_argument("--force", action="store_true", help="download and extract again even if records exist")
    ap.add_argument("--keep-zip", action="store_true", help="keep the zip file after extraction")
    a = ap.parse_args()

    target = os.path.join(a.out_dir, a.ecosystem)
    have = len([f for f in os.listdir(target) if f.endswith(".json")]) if os.path.isdir(target) else 0
    if have and not a.force:
        print(f"{target} already holds {have:,} records - nothing to do (use --force to refresh)")
        return

    os.makedirs(a.out_dir, exist_ok=True)
    url = a.url or URL.format(eco=a.ecosystem)
    if a.zip:
        zip_path, downloaded = a.zip, False
        print(f"using local zip {zip_path}")
    else:
        zip_path, downloaded = os.path.join(a.out_dir, f"{a.ecosystem}-all.zip"), True
        print(f"downloading {url}")
        fetch_zip(url, zip_path)

    if a.force and os.path.isdir(target):
        shutil.rmtree(target)                     # do not mix old and new records
    print(f"extracting to {target} ...")
    n = extract(zip_path, target)
    if n == 0:
        sys.exit("the zip contained no .json records - wrong file?")
    with open(os.path.join(target, "_source.txt"), "w") as f:
        f.write(f"url: {url}\ndownloaded: {time.strftime('%Y-%m-%d %H:%M:%S')}\nrecords: {n}\n")
    if downloaded and not a.keep_zip:
        os.remove(zip_path)
    print(f"done: {n:,} OSV records in {target}")


if __name__ == "__main__":
    main()
