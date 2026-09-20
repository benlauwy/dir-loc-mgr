---
name: testing-dirloc-cli
description: End-to-end testing of dirloc snapshot, restore, and filesystem safety behavior.
---

# Runtime setup
- This is a Python 3.10+ stdlib CLI, with no server, browser, or service login.
- Test scratch trees under `/home/ubuntu`, outside the checkout. Keep evidence and helper scripts outside the managed source tree so they do not become snapshot files.
- Use `python3 <repo>/dirloc.py` during development. A previous noneditable pip install may contain stale code.
- Verify packaging separately with `python3 -m pip install <repo>` using default build isolation, then `dirloc`. Disabling build isolation requires setuptools in the active interpreter and may fail even though normal installation works.

# High-value flow
- Seed distinct small files, a file larger than 192 KiB, and a symlink; save with a description.
- Rename/move across directories, swap two filenames, remove one file, and add unknown content with an existing `_unsorted` collision.
- Assert `diff` exits 1, then compare recursive manifests before/after dry-run. Include paths, full content hashes, symlink targets and mtimes; exclude directory mtimes that can change during legitimate moves.
- Restore and check original bytes, collision suffixes, missing reporting, pruning and absence of `.dirloc/staging-*`.
- Copy to an external output directory and assert source manifest equality.
- Separate duplicate-content fixtures from the golden path; inspect the save warning and JSON `skipped_duplicates`, and verify restore does not move ambiguous content.
- Exercise preflight with an earlier valid move and a later blocked target; compare the whole tree to detect partial mutations.
- A missing saved file intentionally keeps `diff` at exit 1 after restore. Recreate it to demonstrate exit 0.
- For user-visible evidence, maximize a terminal and record real CLI interactions; keep long fixture/check scripts outside the recorded flow and label their assertions clearly.

## Devin Secrets Needed
None.
