# OSV Record Format

Notes on where to find a fix commit in an OSV record, and which records to use.

Full specification: [OSV schema](https://ossf.github.io/osv-schema/#format-overview)

## Finding the fix commit

A record can have a fix commit in a range, in its references, in both, or in neither.

### 1. Ranges

[Schema: `affected[].ranges[].type`](https://ossf.github.io/osv-schema/#affectedrangestype-field)

| `type` | What `fixed` contains | What it means for us |
|---|---|---|
| `GIT` | A commit hash, if the range has a `fixed` entry | The most explicit source of the fix commit |
| `ECOSYSTEM` | A version number | This range gives no commit, so check `references`. If there's no commit there either, it needs further exploration |

```json
"ranges": [{
  "type": "GIT",
  "repo": "https://github.com/owner/name",
  "events": [{ "introduced": "0" }, { "fixed": "<commit hash>" }]
}]
```

### 2. References

[Schema: `references`](https://ossf.github.io/osv-schema/#references-field)

```json
"references": [{
  "type": "FIX",
  "url": "https://github.com/owner/name/commit/<commit hash>"
}]
```

Commit links, by how much to trust them:

| `type` | Use it? | Notes |
|---|---|---|
| `FIX` | Yes | Claims to be the fix. Use only if the URL is a commit, not a pull request |
| `WEB` | Check first | A possible fix only, because the type says nothing about the link |
| `INTRODUCED` | Never | Points to the commit that created the bug |

## Finding the repo

| `type` | Notes |
|---|---|
| `PACKAGE` | The package's home page, often the GitHub repo |

## Record types

Counts are from our November 2026 download. OSV updates daily, so these will change.

| Prefix | Records | Comes from | Documentation |
|---|---:|---|---|
| `MAL` | 11,981 | OpenSSF Malicious Packages | [ossf/malicious-packages](https://github.com/ossf/malicious-packages) |
| `PYSEC` | 7,985 | PyPA | [pypa/advisory-database](https://github.com/pypa/advisory-database) |
| `GHSA` | 6,813 | GitHub | [github/advisory-database](https://github.com/github/advisory-database) |
| `OSV` | 12 | OSS-Fuzz | [google/oss-fuzz-vulns](https://github.com/google/oss-fuzz-vulns) |
| **Total** | **26,791** | | |

### Ignore `MAL` records

`MAL` makes up about 45% of the records. These are malicious packages, not vulnerabilities that get fixed, so they shouldn't count as fix examples.
