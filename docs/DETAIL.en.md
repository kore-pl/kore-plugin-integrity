# kore-plugin-integrity (critical file integrity plugin)

## What it does

Builds a sha256 baseline of critical files and compares on demand, reporting modified, added or removed files. The plugin only reads files and computes hashes and metadata: it never reads file contents, modifies scanned files, escalates privileges or emits events. depth_level=basic, lifecycle=lazy, protocol kore.plugin.v1.

Read methods declare system:read; baseline, restore and schedule.set declare system:admin; plugin-level declaration is system:read + system:admin (method-level narrowing never widens it).

## Key points

- Only third-party dependency: github.com/pengtang1024/kore/pkg/pluginapi v0.1.1; everything else is the standard library.
- Resources: memory_mb 6, cpu_quota 10%, pids_max 16; streaming hashing keeps resident memory independent of file size.
- Methods: baseline, baseline.list, restore, check, status, verify_file, schedule.set, schedule.get (see the Chinese DETAIL.md for the full parameter tables; method names and JSON fields are language-neutral).
- Alerts: file_removed and file_modified (critical), file_added and scan_incomplete (warning); returned in alerts[] only, never delivered externally.

## Installation and verification

Install `integrity` from the plugin marketplace, or import dist/integrity-0.6.0.tar.gz built with make dist. Verify with make check (gofmt, go vet, go test -timeout 200s).

---

简体中文原文见 [DETAIL.md](DETAIL.md)。
