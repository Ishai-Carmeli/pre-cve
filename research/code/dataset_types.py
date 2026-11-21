"""
dataset_types.py - names for the data shapes used by build_dataset_osv.py.

Type hints only: Python ignores them when the scripts run. VS Code uses them to show what a variable
holds when you hover over it.
"""
from collections import Counter
from typing import Any, Literal, NotRequired, TypedDict


# --------------------------------------------------------------------------- reading the OSV records
# one OSV .json file, as json.load returns it
OsvRecord = dict[str, Any]

# where a link to a fix commit was found
Evidence = Literal["git_range", "fix_ref", "web_ref"]

# (repo "owner/name", sha, evidence): one fix-commit link in a record
FixLink = tuple[str, str, Evidence]


class FixInfo(TypedDict):
    """Everything known about one fix commit, merged over all the advisories that point to it."""
    # advisory IDs, e.g. {"PYSEC-2026-4358", "GHSA-..."}
    ids: set[str]
    # earliest advisory date (ISO 8601), "" if unknown
    published: str
    # where links to this commit were found
    evidence: set[Evidence]


# the fix commits of one repo: sha -> FixInfo
RepoFixes = dict[str, FixInfo]

# all fix commits: repo "owner/name" -> RepoFixes
Fixes = dict[str, RepoFixes]


class MalStats(TypedDict):
    """GitHub repos seen in MAL records; used only for the dry-run statistics."""
    # repos mentioned by MAL records
    repos: set[str]
    # repos mentioned by MAL records that have a commit link
    commit_repos: set[str]
    # repos mentioned by real (non-MAL) advisories
    other_repos: set[str]


OsvStats = Counter[str]
"""What happened while reading the OSV records (collect_fixes). Keys:
"records", "unreadable_files", "not_an_osv_record", "withdrawn_skipped", "mal_skipped",
"mal_with_repo", "mal_with_commit_link", "non_pypi_skipped", "records_with_commit",
"records_without_commit", "introduced_ref_skipped", "short_sha_merged", "short_sha_dropped",
and "prefix_<ID prefix>" for each record type (e.g. "prefix_GHSA")."""

EvidenceCounts = Counter[Evidence]
"""How many fix commits have each evidence (count_evidence). Each commit is counted once, by its
strongest evidence (git_range, else fix_ref, else web_ref), so the three counts add up to the number
of unique fix commits."""


# --------------------------------------------------------------------------- the output dataset
class FileChange(TypedDict):
    """One changed code file of a commit."""
    # file path after the commit
    path: str
    # "M" modified, "A" added, "R" renamed
    status: str
    # file content before the commit ("" if the file was added)
    before: str
    # file content after the commit
    after: str


class DatasetRow(TypedDict):
    """One line of the output .jsonl. The last three keys exist only in fix commits (label 1)."""
    repo: str
    sha: str
    # 1 = fix commit, 0 = ordinary commit
    label: int
    # main advisory ID; None for ordinary commits
    vuln: str | None
    # commit message
    message: str
    files: list[FileChange]
    # committer date (ISO 8601)
    commit_date: str | None
    # author date (ISO 8601): when the change was first written
    author_date: str | None
    # all advisory IDs
    vulns: NotRequired[list[str]]
    # earliest advisory date
    published: NotRequired[str | None]
    evidence: NotRequired[list[Evidence]]


RepoStats = Counter[str]
"""What happened while downloading one repo (work_repo). Keys:
"pos" (fix commits written), "neg" (ordinary commits written), "fix_fetch_failed", "fix_unusable",
"repo_unavailable". main() adds them up over all repos, plus "repo_crashed"."""

# what work_repo returns: (repo "owner/name", its RepoStats)
RepoResult = tuple[str, RepoStats]
