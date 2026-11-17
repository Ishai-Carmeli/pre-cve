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

-  It seems like data is splitted by repositories and not commits