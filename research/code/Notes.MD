- commit_date (and published field returned by collect_fixes) may not be a good option to test negative day window
- excart fixes only ignores INTRODUCED, and not EVIDENCE': 3, 'ADVISORY': 1, 'PACKAGE': 1. The data is not entirely clean.
- => 1107 repos, 5319 unique fix commits   (evidence: {'web_ref': 5214, 'git_range': 1065, 'fix_ref': 1490}) : We should change such that when a commit has a fix evidence, it is a fix ref, else if it has a web_ref and not a fix_ref, it is a web_ref

- Some repos have the name apache/airflow. How do we know what is the same package? Can we be sure that repo name is the package name?


- Your dataset has 7,364 rows:

Label	Meaning	Count
1	Fix commits (positives)	2,460
0	Ordinary commits (negatives)	4,904

It may not be enough, and pysecdb could be a better choice.

- The same fix on several branches If one lands in training and the other in the test set, the test score is inflated.

Commit f6860f1 fixes the bug on the main branch.
Commit 5525f8c is probably the same change copied to a release branch. The diff is almost identical, with the same lines removed and added.

Solution: commits should be group by repositries.

- It seems like data is splitted by repositories and not commits

- We get atmost 12 commits out of every repository.

- Finally block in work_repo ignore errors deleting tmp git folders.

- pos_full contains only the fixes handled so far. When Step 4 picks negatives right after the first successful fix, the repo's later fixes aren't in pos_full yet. The fixes are ordered by advisory date, not commit date. So a later fix could have been committed before the first one, appear in its history, and be picked as a negative. It would then also be added as a positive when the loop reaches it.

- Negatives come from the 120 commits before the fix with the earliest advisory, not before the oldest fix. we might be adding the same fix as negative and positive

- work_repo: Failed repositories aren't retried between runs.

- Cherry-pick = copying one commit's change to another branch as a new commit (new sha). Projects do it to ship a security fix to every supported release (e.g. main + 1.x). Spot copies: same vuln + same author_date but different commit_date, or "(cherry picked from commit <sha>)" in the message.

- commit_date is not "when the fix landed on main". It is when this commit was created/re-created (rebase, squash, cherry-pick, amend). author_date = when the change was first written. For a PR merged with a merge commit, the landing time is the merge commit's date. Exact: git rev-list --first-parent --ancestry-path <sha>..origin/main | tail -1


- The file name filtering pontentially skips alot of important sample for the dataset
The mistake: it also throws away a code file if the file is named after one of these words:
doc docs example examples change changes changelog news license readme


- record: skips huge files instead of saving the diff.
- record: saves only at most 15 files with the most change in a commit.