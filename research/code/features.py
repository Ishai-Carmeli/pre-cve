"""
features.py - turn a commit (list of before/after files) into model features.
Used identically at training time and at prediction time.

Commit message is deliberately NOT used (silent fixes hide it).

The text document holds tokens from several independent "families". Each token starts with a
prefix, so a model can be trained on any subset (see FAMILIES / filter_text):

  base  A:/R:      words in ADDED / REMOVED lines. Identifiers are kept whole (`yaml.load`) and split
                   into sub-words (`sanitize_path` -> sanitize, path) so the model generalises.
  calls K:/M:      data-driven version of "dangerous call replaced by safe one": every function call /
                   import whose count went up (+) or down (-) in the file.
  ast   S:         structure delta: how many nodes of each type, and parent>child pairs, were added (+)
                   or removed (-) in the syntax tree. e.g. S:+If>Raise = a new guard clause.
  ctx   F:/C:/X:   where the change happens: names of the enclosing function / class, and the
                   unchanged lines right around the change.
  path  P:         words of the file path (can leak project names - off by default).

struct: numeric features (diff size, statement kinds in added/removed lines, weights of the
hand-written rules in security_patch_detector that fired, ...).
"""
from __future__ import annotations

import ast
import difflib
import math
import os
import re
import warnings
from collections import Counter

import security_patch_detector as spd

MAX_TEXT_CHARS = 60_000
MAX_CTX_CHARS = 20_000
MAX_REGIONS = 200

FAMILIES = {"base": ("A:", "R:"), "calls": ("K:", "M:"), "ast": ("S:",), "ctx": ("F:", "C:", "X:"),
            "path": ("P:",)}
LEGACY_FAMILIES = ("base", "path")        # what model files trained before families existed used

_WHOLE = re.compile(r"[A-Za-z_][\w.]*")
_SUB = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_SENSITIVE_PATH = re.compile(
    r"(sandbox|secur|auth|crypt|csrf|session|sanitiz|escap|permission|password|token|ssl|tls|sign|jwt|"
    r"oauth|cookie|xml|serializ|pickle|upload|shell|exec|parse|url|path|file|http|request|login|acl|"
    r"validat|filter|template|render)", re.I)
_STMT = {
    "raise": r"^\s*raise\b", "if": r"^\s*(el)?if\b", "try": r"^\s*(try|except|finally)\b",
    "assert": r"^\s*assert\b", "return": r"^\s*return\b", "len": r"\blen\(", "in": r"\b(not\s+)?in\b",
    "isinstance": r"\bisinstance\(", "import": r"^\s*(from|import)\b", "def": r"^\s*(async\s+)?def\b",
    "class": r"^\s*class\b", "comment": r"^\s*#", "string": r"['\"]", "regex": r"\bre\.(compile|match|search|sub|fullmatch)",
    "startswith": r"\.(startswith|endswith)\(", "none": r"\bis (not )?None\b", "eq": r"==|!=",
    "limit": r"(?i)(max|limit|size|length|depth|timeout)", "os": r"\bos\.|\bpath\b|\bPath\(",
    "bytes": r"\bbytes|bytearray|memoryview|\bbuf", "c_unsafe": r"\b(memcpy|strcpy|malloc|free|sizeof)\b",
}
_STMT_RE = {k: re.compile(v) for k, v in _STMT.items()}


def filter_text(text: str, families) -> str:
    """Keep only the tokens that belong to the given families."""
    prefixes = tuple(p for f in families for p in FAMILIES[f])
    return " ".join(w for w in text.split() if w.startswith(prefixes))


def _split_tokens(line: str, prefix: str) -> list[str]:
    toks = []
    for w in _WHOLE.findall(line):
        toks.append(prefix + w.lower())
        for part in w.replace(".", "_").split("_"):
            for sub in _SUB.findall(part):
                toks.append(prefix + "~" + sub.lower())
    return toks


def _parse(code: str):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return ast.parse(code)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return None


def _spans(tree) -> list:
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append((n.lineno, getattr(n, "end_lineno", n.lineno),
                        "C:" if isinstance(n, ast.ClassDef) else "F:", n.name))
    return out


def _enclosing(spans, line: int) -> list:
    """Innermost function and innermost class that contain `line`."""
    best: dict = {}
    for start, end, kind, name in spans:
        if start <= line <= end and (kind not in best or end - start < best[kind][0]):
            best[kind] = (end - start, name)
    return [(k, v[1]) for k, v in best.items()]


def _shapes(tree) -> Counter:
    c: Counter = Counter()
    for node in ast.walk(tree):
        tn = type(node).__name__
        c[tn] += 1
        for ch in ast.iter_child_nodes(node):
            c[tn + ">" + type(ch).__name__] += 1
        if isinstance(node, ast.Compare):
            for op in node.ops:
                c["Cmp:" + type(op).__name__] += 1
        elif isinstance(node, ast.BoolOp):
            c["Bool:" + type(node.op).__name__] += 1
        elif isinstance(node, ast.UnaryOp):
            c["Un:" + type(node.op).__name__] += 1
    return c


def _delta_tokens(before: Counter, after: Counter, prefix: str, lower: bool = False, repeat: int = 3) -> list[str]:
    out = []
    for k in set(before) | set(after):
        d = after.get(k, 0) - before.get(k, 0)
        if d:
            name = k.lower() if lower else k
            out.extend([f"{prefix}{'+' if d > 0 else '-'}{name}"] * min(abs(d), repeat))
    return out


def commit_features(files: list[dict], families=None) -> tuple[str, dict]:
    """files: [{'path','before','after'}, ...]  ->  (text_document, struct_features).
    `families`: restrict the text to these families (default: keep everything)."""
    toks: list[str] = []
    struct: Counter = Counter()
    added_total = removed_total = regions_total = 0
    chars = ctx_chars = 0
    rule_w: dict[str, float] = {}
    sensitive = 0
    n_py = 0

    for f in files:
        path, before, after = f["path"], f["before"], f["after"]
        for part in path.split("/"):
            toks.extend(_split_tokens(part, "P:"))
        bl, al = before.splitlines(), after.splitlines()
        sm = difflib.SequenceMatcher(None, bl, al)
        ops = [op for op in sm.get_opcodes() if op[0] != "equal"]
        a_lines, r_lines = [], []
        for tag, i1, i2, j1, j2 in ops:
            if tag in ("replace", "delete"):
                r_lines.extend(bl[i1:i2])
            if tag in ("replace", "insert"):
                a_lines.extend(al[j1:j2])
        added_total += len(a_lines)
        removed_total += len(r_lines)
        regions_total += len(ops)
        if _SENSITIVE_PATH.search(os.path.basename(path)):
            sensitive += 1
        for side, lines in (("A:", a_lines), ("R:", r_lines)):
            for line in lines:
                if chars > MAX_TEXT_CHARS:
                    break
                chars += len(line)
                toks.extend(_split_tokens(line, side))
                for name, rx in _STMT_RE.items():
                    if rx.search(line):
                        struct[f"{side}{name}"] += 1

        # ---- context: unchanged lines around each change -------------------------------- #
        for tag, i1, i2, j1, j2 in ops[:MAX_REGIONS]:
            for line in bl[max(0, i1 - 3):i1] + bl[i2:i2 + 3]:
                s = line.strip()
                if s and not s.startswith("#") and ctx_chars < MAX_CTX_CHARS:
                    ctx_chars += len(s)
                    toks.extend(_split_tokens(s, "X:"))

        is_py = path.endswith((".py", ".pyx"))
        if is_py:
            n_py += 1
            try:
                ev, _ = spd.heuristic_evidence(before, after)
            except Exception:
                ev = []
            for e in ev:
                if e.weight > 0:
                    rule_w[e.rule_id] = max(rule_w.get(e.rule_id, 0.0), e.weight)
            fb, fa = spd.extract_features(before), spd.extract_features(after)
            if fb.parsed and fa.parsed:
                struct["ast_same"] += int(fb.normalized_dump == fa.normalized_dump)
                struct["d_guard"] += fa.guard_count - fb.guard_count
                struct["d_len_checks"] += fa.len_checks - fb.len_checks
                struct["d_isinstance"] += fa.isinstance_checks - fb.isinstance_checks
                struct["d_calls"] += sum(fa.calls.values()) - sum(fb.calls.values())
                struct["d_imports"] += sum(fa.imports.values()) - sum(fb.imports.values())
                # ---- calls / imports that appeared or disappeared ------------------------- #
                toks.extend(_delta_tokens(fb.calls, fa.calls, "K:", lower=True))
                toks.extend(_delta_tokens(fb.call_tails, fa.call_tails, "K:~", lower=True))
                toks.extend(_delta_tokens(fb.imports, fa.imports, "M:", lower=True, repeat=1))
            # ---- syntax-tree shape delta + enclosing function / class names --------------- #
            tb, ta = _parse(before) if before else None, _parse(after)
            if ta is not None and (tb is not None or not before):
                toks.extend(_delta_tokens(_shapes(tb) if tb is not None else Counter(), _shapes(ta), "S:"))
                spans_a = _spans(ta)
                spans_b = _spans(tb) if tb is not None else []
                names = set()
                for tag, i1, i2, j1, j2 in ops[:MAX_REGIONS]:
                    if tag in ("replace", "insert"):
                        names.update(_enclosing(spans_a, j1 + 1))
                        names.update(_enclosing(spans_a, max(j1 + 1, j2)))
                    else:
                        names.update(_enclosing(spans_b, i1 + 1))
                for kind, name in names:
                    toks.extend(_split_tokens(name, kind))

    out = {k: math.log1p(v) if v >= 0 else -math.log1p(-v) for k, v in struct.items()}
    out.update({
        "n_files": math.log1p(len(files)), "n_py": math.log1p(n_py),
        "lines_added": math.log1p(added_total), "lines_removed": math.log1p(removed_total),
        "net_lines": math.copysign(math.log1p(abs(added_total - removed_total)), added_total - removed_total),
        "sensitive_files": math.log1p(sensitive),
        "sensitive_frac": sensitive / max(1, len(files)),
        "small_change": float(added_total + removed_total <= 30),
        "tiny_change": float(added_total + removed_total <= 8),
        "n_regions": math.log1p(regions_total),
    })
    for rid, w in rule_w.items():
        out["rule:" + rid] = w
    out["rule_total"] = sum(rule_w.values())
    text = " ".join(toks)
    return (filter_text(text, families) if families else text), out
