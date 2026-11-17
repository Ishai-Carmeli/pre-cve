"""
commit_analyzer.py  -  detect SILENT security fixes in git commits
===================================================================

Works at the *commit* level, before any release / CVE / OSV entry exists:

    analyze_commit(repo, sha)        -> CommitVerdict   (one commit)
    scan_range(repo, "A..B")         -> list[CommitVerdict]
    watch(repo, state_file, ...)     -> new commits since last run, flagged ones returned

Evidence = (a) per-file code analysis from security_patch_detector.analyze()
           (AST patterns + Bandit delta + optional Semgrep delta) on the
           before/after version of every changed source file, and
           (b) the commit message (weak signal, capped below the threshold unless
           it names an explicit CVE/GHSA id) and commit-level context
           (tests/docs only, huge refactor ...).
Advisory databases are NOT consulted: by definition they don't know the fix yet.

CLI:
    python commit_analyzer.py analyze  /path/to/repo  <sha>
    python commit_analyzer.py scan     /path/to/repo  --range v1.0..v1.1   (or --last 50)
    python commit_analyzer.py watch    https://github.com/org/pkg  --state state.json
Repo may be a local path or a URL (cloned into --workdir, default ./.repos).
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

import security_patch_detector as spd
from features import LEGACY_FAMILIES, commit_features
from security_patch_detector import Evidence

THRESHOLD = spd.SECURITY_THRESHOLD
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.joblib")
_MODEL = None


def load_model(path: str = MODEL_PATH):
    """Load the trained classifier once (None if the file is missing)."""
    global _MODEL
    if _MODEL is None and os.path.exists(path):
        import joblib
        _MODEL = joblib.load(path)
    return _MODEL


def model_probability(files: list[dict]) -> Optional[float]:
    m = load_model()
    if m is None or not files:
        return None
    import train_model
    text, struct = commit_features(files, m.get("families", LEGACY_FAMILIES))
    return float(train_model.predict(m["models"], [text], [struct])[2][0])


MAX_FILE_BYTES = 400_000
MAX_SOURCE_FILES = 40          # more than this -> only the 40 biggest diffs are analysed

CODE_EXT = (".py", ".pyx", ".pxd", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".go", ".js", ".ts", ".java")
_DOC_RE = re.compile(r"(^|/)(docs?|doc|examples?|changes?|changelog|news|license|readme|\.github)(/|\.|$)", re.I)
_VENDOR_RE = re.compile(r"(^|/)(vendor|vendored|third[_-]?party|node_modules|static|dist|build|_vendor)(/|$)|"
                        r"\.min\.(js|css)$|(^|/)(jquery|underscore|bootstrap)[^/]*\.js$", re.I)
_TEST_RE = re.compile(r"(^|/)(tests?|testing)(/|$)|(^|/)test_[^/]*$|_test\.py$|(^|/)conftest\.py$", re.I)


# --------------------------------------------------------------------------- #
#  git helpers                                                                #
# --------------------------------------------------------------------------- #

class GitError(RuntimeError):
    pass


def git(repo: str, *args: str, check: bool = True) -> str:
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, timeout=300)
    if p.returncode != 0 and check:
        raise GitError(p.stderr.decode("utf-8", "replace").strip() or f"git {' '.join(args)} failed")
    return p.stdout.decode("utf-8", "replace")


def ensure_repo(repo: str, workdir: str = ".repos") -> str:
    """Return a local path. URLs are cloned (bare-ish, full history) into workdir."""
    if os.path.isdir(repo):
        return repo
    if not re.match(r"^(https?://|git@|ssh://)", repo):
        raise GitError(f"not a directory or URL: {repo}")
    os.makedirs(workdir, exist_ok=True)
    local = os.path.join(workdir, hashlib.sha1(repo.encode()).hexdigest()[:12])
    if not os.path.isdir(os.path.join(local, ".git")):
        subprocess.run(["git", "clone", "--quiet", repo, local], check=True, timeout=900)
    return local


# --------------------------------------------------------------------------- #
#  commit message signals                                                     #
# --------------------------------------------------------------------------- #

_EXPLICIT_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+)\b", re.I)
_STRONG_MSG = re.compile(
    r"\b(security|vulnerab\w*|exploit\w*|xss|csrf|ssrf|xxe|rce|sql\s*injection|injection|"
    r"path\s*traversal|directory\s*traversal|traversal|arbitrary\s*(code|file)|"
    r"denial[\s-]of[\s-]service|dos|redos|overflow|use[\s-]after[\s-]free|"
    r"sandbox\s*(escape|bypass)|bypass(es|ed)?|privilege|escalat\w*|untrusted|malicious|"
    r"sanitiz\w*|unsafe|insecure|harden\w*|cwe-\d+|leak(s|ed|ing)?\s*(secret|token|password|credential|memory)?)\b", re.I)
_WEAK_MSG = re.compile(
    r"\b(validat\w*|prevent\w*|disallow\w*|forbid\w*|restrict\w*|reject\w*|escape[sd]?|"
    r"constant[\s-]time|timing|limit(s|ed)?|max(imum)?\s*(size|length|depth)|crash(es)?|"
    r"auth\w*|permission\w*|certificate|tls|ssl|verify|signature|secret|token|password)\b", re.I)
_NOISE_MSG = re.compile(
    r"^(\W*)(docs?|typo|spelling|readme|changelog|release|bump|version|merge|ci|lint|format|style|"
    r"pre-commit|dependabot|update (docs?|readme|changelog|dependencies|requirements)|add tests?|test)\b|"
    r"\b(typo|whitespace|flake8|black|isort|mypy|type hints?|refactor\w*|cleanup|clean up|rename)\b", re.I)


def message_evidence(message: str) -> list[Evidence]:
    ev: list[Evidence] = []
    if not message.strip():
        return ev
    if _EXPLICIT_ID.search(message):
        ids = sorted(set(m.upper() for m in _EXPLICIT_ID.findall(message)))
        ev.append(Evidence("message", "msg-explicit-id", f"message references advisory id(s) {ids} "
                           "(not silent, but confirms a security fix)", 5.0, "known advisory"))
        return ev
    strong = sorted({m.group(0).lower() for m in _STRONG_MSG.finditer(message)})
    weak = sorted({m.group(0).lower() for m in _WEAK_MSG.finditer(message)})
    if strong:
        ev.append(Evidence("message", "msg-security-words", f"security wording in message: {strong[:5]}",
                           min(1.0 + 0.5 * len(strong), 2.5), "message"))
    elif weak:
        ev.append(Evidence("message", "msg-weak-words", f"validation-style wording in message: {weak[:5]}",
                           min(0.4 * len(weak), 1.0), "message"))
    subject = message.strip().splitlines()[0]
    if _NOISE_MSG.search(subject):
        ev.append(Evidence("message", "msg-noise", "subject looks like docs/refactor/release housekeeping",
                           -1.5, "negative"))
    return ev


# --------------------------------------------------------------------------- #
#  result object                                                              #
# --------------------------------------------------------------------------- #

@dataclass
class CommitVerdict:
    repo: str
    sha: str
    subject: str
    author: str = ""
    date: str = ""
    is_security_update: bool = False
    verdict: str = "NOT_SECURITY"       # binary: SECURITY_UPDATE | NOT_SECURITY
    score: float = 0.0                  # hand-written rule score
    probability: Optional[float] = None  # trained model's probability (None if no model file)
    confidence: float = 0.0
    summary: str = ""
    categories: list = field(default_factory=list)
    files_analyzed: list = field(default_factory=list)
    files_skipped: int = 0
    evidence: list = field(default_factory=list)
    skipped_reason: str = ""

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        return d

    def to_json(self, **kw) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, **kw)


# --------------------------------------------------------------------------- #
#  single commit                                                              #
# --------------------------------------------------------------------------- #

def _changed_files(repo: str, sha: str, parent: Optional[str]):
    args = ["diff-tree", "--no-commit-id", "--name-status", "-r", "-M", "--no-renames"] if False else \
        ["diff-tree", "--no-commit-id", "--name-status", "-r", "-M"]
    out = git(repo, *args, "--root", sha) if parent is None else git(repo, *args, sha)
    files = []
    for line in out.splitlines():
        parts = line.split("\t")
        status = parts[0][0]
        if status == "R":
            files.append(("M", parts[1], parts[2]))
        elif status in "MA":
            files.append((status, parts[1], parts[1]))
        # deletions / type changes are ignored
    return files


def _show(repo: str, rev: str, path: str) -> Optional[str]:
    try:
        text = git(repo, "show", f"{rev}:{path}")
    except GitError:
        return None
    return text if len(text) <= MAX_FILE_BYTES else None


def analyze_commit(repo: str, sha: str, *, use_message: bool = True, use_bandit: bool = True,
                   use_semgrep: bool = False, threshold: float = THRESHOLD, use_model: bool = True,
                   prob_threshold: Optional[float] = None) -> CommitVerdict:
    sha = git(repo, "rev-parse", "--verify", sha).strip()
    meta = git(repo, "log", "-1", "--format=%an%x00%aI%x00%B", sha).split("\x00", 2)
    author, date, message = (meta + ["", "", ""])[:3]
    v = CommitVerdict(repo=repo, sha=sha, subject=(message.strip().splitlines() or [""])[0],
                      author=author, date=date)

    parents = git(repo, "rev-list", "--parents", "-n", "1", sha).split()[1:]
    if len(parents) > 1:
        v.skipped_reason = "merge commit (its changes are analysed in the commits it merges)"
        v.summary = "Skipped: merge commit"
        return v
    parent = parents[0] if parents else None

    changed = _changed_files(repo, sha, parent)
    source = [(s, old, new) for s, old, new in changed
              if new.lower().endswith(CODE_EXT) and not _TEST_RE.search(new) and not _DOC_RE.search(new)
              and not _VENDOR_RE.search(new)]
    v.files_skipped = len(changed) - len(source)

    all_ev: list[Evidence] = []
    if use_message:
        all_ev += message_evidence(message)

    if not source:
        all_ev.append(Evidence("commit", "no-source-files",
                               "no production source files changed (only tests/docs/config)", -6.0, "negative"))
        return _finalize(v, all_ev, threshold)

    # biggest diffs first; cap the work
    sized = []
    for s, old, new in source:
        after = _show(repo, sha, new)
        before = _show(repo, parent, old) if (parent and s != "A") else ""
        if after is None or before is None:
            v.files_skipped += 1
            continue
        sized.append((abs(len(after) - len(before)) + 1, new, before, after))
    sized.sort(reverse=True)
    if len(sized) > MAX_SOURCE_FILES:
        v.files_skipped += len(sized) - MAX_SOURCE_FILES
        sized = sized[:MAX_SOURCE_FILES]

    lines_changed = 0
    per_rule: dict[str, list[Evidence]] = {}
    for _, path, before, after in sized:
        r = spd.analyze(before, after, filename=path, use_bandit=use_bandit, use_semgrep=use_semgrep,
                        use_network=False, threshold=threshold)
        v.files_analyzed.append({"path": path, "score": r.score, "verdict": r.verdict})
        lines_changed += r.diff_stats.get("lines_added", 0) + r.diff_stats.get("lines_removed", 0)
        for e in r.evidence:
            if e.weight > 0:          # per-file negatives (cosmetic etc.) must not cancel other files
                per_rule.setdefault(e.rule_id, []).append(
                    dataclasses.replace(e, description=f"{path}: {e.description}"))

    # same rule firing in many files: strongest + 20% of each extra, capped at 1.5x strongest
    for rule, evs in per_rule.items():
        evs.sort(key=lambda e: -e.weight)
        top = evs[0]
        extra = 0.2 * sum(e.weight for e in evs[1:])
        w = min(top.weight + extra, top.weight * 1.5)
        all_ev.append(dataclasses.replace(top, weight=round(w, 2)))

    if lines_changed > 800:
        all_ev.append(Evidence("commit", "huge-commit", f"very large change ({lines_changed} lines): "
                               "usually a refactor/feature, signals are diluted", -1.0, "negative"))
    _finalize(v, all_ev, threshold)
    if use_model:
        p = model_probability([{"path": path, "before": b, "after": a} for _, path, b, a in sized])
        if p is not None:
            _apply_model(v, p, explicit_id=any(e.rule_id == "msg-explicit-id" for e in all_ev),
                         prob_threshold=prob_threshold)
    return v


def _apply_model(v: CommitVerdict, p: float, explicit_id: bool, prob_threshold: Optional[float] = None) -> None:
    """Binary decision from the trained model; rule evidence stays attached as the explanation.
    prob_threshold is the dial: lower = catches more fixes but more false alarms (default: the
    F1-optimal threshold measured on unseen repositories, stored in model.joblib)."""
    th = prob_threshold if prob_threshold is not None else load_model()["thresholds"]["binary"]
    v.probability = round(p, 3)
    v.confidence = v.probability
    v.is_security_update = p >= th or explicit_id
    v.verdict = "SECURITY_UPDATE" if v.is_security_update else "NOT_SECURITY"
    why = next((e["description"] for e in v.evidence if e["weight"] > 0 and e["source"] != "message"), "")
    v.summary = ("Security update" if v.is_security_update else "Not a security update") + \
        f" (model probability {p:.0%}, threshold {th:.0%})" + \
        (f"; rule hint: {why}" if why and v.is_security_update else "")


def _finalize(v: CommitVerdict, ev: list[Evidence], threshold: float) -> CommitVerdict:
    score = spd._aggregate(ev)
    v.score = score
    v.confidence = spd._confidence(score) if threshold == THRESHOLD else \
        round(1 / (1 + 2.718281828 ** (-(score - threshold) / 1.2)), 3)
    v.is_security_update = score >= threshold
    v.verdict = "SECURITY_UPDATE" if v.is_security_update else "NOT_SECURITY"
    pos = sorted([e for e in ev if e.weight > 0], key=lambda e: -e.weight)
    v.categories = sorted({e.category for e in pos if e.category not in ("lexical", "general", "message")})
    v.evidence = [dataclasses.asdict(e) for e in sorted(ev, key=lambda e: -abs(e.weight))]
    if v.is_security_update:
        v.summary = "Likely security fix – " + (pos[0].description if pos else "")
    else:
        v.summary = "Not a security fix" + ("" if not pos else f" (strongest weak signal: {pos[0].description})")
    return v


# --------------------------------------------------------------------------- #
#  ranges + watching                                                          #
# --------------------------------------------------------------------------- #

def scan_range(repo: str, rev_range: str, **kw) -> list[CommitVerdict]:
    shas = git(repo, "rev-list", "--reverse", "--no-merges", rev_range).split()
    return [analyze_commit(repo, s, **kw) for s in shas]


def watch(repo: str, state_file: str, *, branch: Optional[str] = None, workdir: str = ".repos",
          backfill: int = 0, on_alert: Optional[Callable[[CommitVerdict], None]] = None, **kw):
    """One polling step (run it from cron / Celery beat / a management command).
    Fetches the repo, analyses every commit that appeared since the last call and
    returns (all_verdicts, flagged). The first call only records a baseline
    (use backfill=N to analyse the latest N commits immediately)."""
    local = ensure_repo(repo, workdir)
    if not os.path.isdir(repo):
        git(local, "fetch", "--quiet", "origin")
        branch = branch or git(local, "symbolic-ref", "--short", "refs/remotes/origin/HEAD").strip().split("/", 1)[-1]
        head = f"origin/{branch}"
    else:
        head = branch or "HEAD"
    tip = git(local, "rev-parse", head).strip()

    state = {}
    if os.path.exists(state_file):
        with open(state_file) as fh:
            state = json.load(fh)
    last = state.get(repo)
    if last is None:
        rng = f"{head}~{backfill}..{head}" if backfill else None
    elif last == tip:
        rng = None
    else:
        rng = f"{last}..{head}"
    verdicts = scan_range(local, rng, **kw) if rng else []
    flagged = [x for x in verdicts if x.is_security_update]
    for x in flagged:
        x.repo = repo
        if on_alert:
            on_alert(x)
    state[repo] = tip
    with open(state_file, "w") as fh:
        json.dump(state, fh, indent=2)
    return verdicts, flagged


def post_webhook(url: str) -> Callable[[CommitVerdict], None]:
    def _send(v: CommitVerdict):
        req = urllib.request.Request(url, data=v.to_json().encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    return _send


# --------------------------------------------------------------------------- #
#  CLI                                                                        #
# --------------------------------------------------------------------------- #

def _print(v: CommitVerdict, verbose: bool = True) -> None:
    flag = "🔴" if v.is_security_update else "🟢"
    prob = f"p={v.probability:.0%}" if v.probability is not None else f"score={v.score}"
    print(f"{flag} {v.sha[:10]}  {prob:<9} {v.subject[:70]}")
    if verbose and (v.is_security_update or v.evidence):
        for e in v.evidence[:6]:
            print(f"      [{e['weight']:>5}] {e['source']:<9} {e['description'][:110]}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Detect silent security fixes in git commits")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("analyze", "scan", "watch"):
        sp = sub.add_parser(name)
        sp.add_argument("repo")
        sp.add_argument("--json", action="store_true")
        sp.add_argument("--no-message", action="store_true", help="ignore commit message (pure code signal)")
        sp.add_argument("--semgrep", action="store_true", help="also run Semgrep (slower)")
        sp.add_argument("--no-bandit", action="store_true")
        sp.add_argument("--no-model", action="store_true", help="rules only, ignore model.joblib")
        sp.add_argument("--prob-threshold", type=float, default=None,
                        help="model probability needed to call a commit a security update "
                             "(default: F1-optimal from model.joblib, ~0.47; 0.80 = strict)")
        sp.add_argument("--threshold", type=float, default=THRESHOLD)
        sp.add_argument("--workdir", default=".repos")
        if name == "analyze":
            sp.add_argument("sha")
        if name == "scan":
            sp.add_argument("--range")
            sp.add_argument("--last", type=int, default=0)
            sp.add_argument("--only-flagged", action="store_true")
        if name == "watch":
            sp.add_argument("--state", default="watch_state.json")
            sp.add_argument("--branch")
            sp.add_argument("--backfill", type=int, default=0)
            sp.add_argument("--webhook")
    a = p.parse_args(argv)
    kw = dict(use_message=not a.no_message, use_semgrep=a.semgrep, use_bandit=not a.no_bandit,
              threshold=a.threshold, use_model=not a.no_model,
              prob_threshold=a.prob_threshold)
    if a.cmd == "analyze":
        v = analyze_commit(ensure_repo(a.repo, a.workdir), a.sha, **kw)
        print(v.to_json(indent=2)) if a.json else _print(v)
        return 1 if v.is_security_update else 0
    if a.cmd == "scan":
        local = ensure_repo(a.repo, a.workdir)
        rng = a.range or f"HEAD~{a.last or 20}..HEAD"
        vs = scan_range(local, rng, **kw)
        if a.json:
            print(json.dumps([x.to_dict() for x in vs], ensure_ascii=False, indent=2))
        else:
            for x in vs:
                if x.is_security_update or not a.only_flagged:
                    _print(x, verbose=x.is_security_update)
            print(f"\n{sum(x.is_security_update for x in vs)} security updates out of {len(vs)} commits")
        return 0
    hook = post_webhook(a.webhook) if a.webhook else None
    vs, flagged = watch(a.repo, a.state, branch=a.branch, workdir=a.workdir, backfill=a.backfill,
                        on_alert=hook, **kw)
    if a.json:
        print(json.dumps([x.to_dict() for x in flagged], ensure_ascii=False, indent=2))
    else:
        print(f"{len(vs)} new commits, {len(flagged)} flagged")
        for x in flagged:
            _print(x)
    return 0


if __name__ == "__main__":
    sys.exit(main())
