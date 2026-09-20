# dir-loc-mgr

`dirloc` saves the layout of a directory (which file lives at which path) and
restores it later, after files have been renamed or shuffled around.

Files are identified by **content**, not by name: a fingerprint made of the
file size plus a SHA-256 over the first, middle and last 64 KiB (files up to
192 KiB are hashed in full). Renaming or moving a file does not change its
fingerprint, so `restore` can put it back where it belongs.

Pure Python 3.10+, standard library only.

## Install

```sh
pip install .          # gives you a `dirloc` command
# or just run it directly:
python3 dirloc.py --help
```

## Usage

```sh
dirloc save  [DIR] -d "description"        # record the layout of DIR (default: .)
dirloc list  [DIR]                          # list snapshots with date, file count, description
dirloc show  [DIR] -s SNAPSHOT              # print what a snapshot contains
dirloc diff  [DIR] -s SNAPSHOT              # show what restore would do (exit 1 if anything differs)
dirloc restore [DIR] -s SNAPSHOT [--dry-run] [-o OUT_DIR]
dirloc delete [DIR] -s SNAPSHOT
dirloc fingerprint FILE...                  # print fingerprints
```

`SNAPSHOT` can be `latest` (the default), a snapshot id, a unique id prefix,
or a substring of the description, e.g. `dirloc restore -s "before reorg"`.

Snapshots are JSON files in `DIR/.dirloc/`. Give one a stable name with
`dirloc save -n NAME -d "..."`; otherwise the id is a timestamp plus a short
random suffix.

### Restore semantics

Restore compares the fingerprints of the files currently in `DIR` with the
snapshot:

| Situation                                  | In-place (default)                              | `--output-dir OUT`                      |
| ------------------------------------------ | ----------------------------------------------- | --------------------------------------- |
| Content found, at a different path         | moved to the saved path                         | copied to `OUT/<saved path>`            |
| Content found, already at the saved path   | left alone                                      | copied to `OUT/<saved path>`            |
| Content in snapshot but not found          | reported as `missing`                           | reported as `missing`                   |
| File present but not in snapshot           | moved to `DIR/_unsorted/<current path>`         | copied to `OUT/_unsorted/<current path>` |
| File already under `DIR/_unsorted/`        | left alone                                      | copied as-is                            |
| Content was duplicated at save time        | left alone (`keep`)                             | copied as-is                            |

Nothing is ever deleted. Conflicts (a symlink in the way, a non-empty
directory at a target path) are detected before anything is touched, and the
restore refuses to run. In-place restore then moves every file through a
staging directory, so swaps and chains (`a -> b`, `b -> c`) are safe; if a
move fails midway, all moves are rolled back (and if even that fails, the
files still in transit are left in `.dirloc/staging-*` and the path is
reported, so nothing is lost). Directories left empty by the moves are
removed. `--dry-run` (or `diff`) prints the plan without touching anything.

### Duplicates

If two files in `DIR` have identical content when you `save`, they cannot be
told apart later, so both are skipped with a warning (they are still listed in
the snapshot under `skipped_duplicates`, and restore leaves any copies of that
content where they are). If duplicates appear *after* a save,
the copy already at the saved path (or the first one, sorted) is used and the
rest go to `_unsorted/`.

Symlinks and the `.dirloc/` directory itself are ignored.

## Development

```sh
python3 -m unittest discover -s tests -v
```
