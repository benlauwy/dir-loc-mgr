#!/usr/bin/env python3
"""dirloc - save and restore the layout (paths + filenames) of a directory.

Files are identified by a content fingerprint (size + hash of head/middle/tail
chunks), so they can be renamed or moved around freely and later put back where
they were when a snapshot was taken.

Snapshots are stored as JSON files under ``<dir>/.dirloc/``.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

__version__ = "0.1.0"

STORE_DIR = ".dirloc"
UNSORTED_DIR = "_unsorted"
STAGING_PREFIX = "staging-"
CHUNK_SIZE = 64 * 1024
FORMAT_VERSION = 1
FINGERPRINT_SCHEME = f"size+sha256(head{CHUNK_SIZE},mid{CHUNK_SIZE},tail{CHUNK_SIZE})"
SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class DirlocError(Exception):
    pass


def validate_snapshot_name(name: str) -> str:
    if name == "latest" or not SNAPSHOT_NAME_RE.match(name):
        raise DirlocError(f"invalid snapshot name {name!r}: use letters, digits, '.', '_' or '-' (not 'latest')")
    return name


def validate_rel_path(rel: str) -> str:
    """Reject paths that could escape the managed directory or touch the snapshot store."""
    bad = (
        not isinstance(rel, str)
        or not rel
        or rel.startswith("/")
        or (os.sep == "\\" and ("\\" in rel or ":" in rel))
        or any(part in ("", ".", "..") for part in rel.split("/"))
        or rel.split("/", 1)[0] == STORE_DIR
    )
    if bad:
        raise DirlocError(f"unsafe path in snapshot: {rel!r}")
    return rel


# --------------------------------------------------------------------------- #
# Fingerprinting
# --------------------------------------------------------------------------- #


def fingerprint(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    """Return ``"<size>:<hash>"`` for the file at *path*.

    Files up to ``3 * chunk_size`` bytes are hashed in full. Larger files hash
    the first, middle and last ``chunk_size`` bytes, so the cost is bounded
    regardless of file size.
    """
    size = path.stat().st_size
    h = hashlib.sha256()
    with path.open("rb") as fh:
        if size <= 3 * chunk_size:
            for block in iter(lambda: fh.read(chunk_size), b""):
                h.update(block)
        else:
            h.update(fh.read(chunk_size))
            fh.seek(size // 2 - chunk_size // 2)
            h.update(fh.read(chunk_size))
            fh.seek(size - chunk_size)
            h.update(fh.read(chunk_size))
    return f"{size}:{h.hexdigest()[:32]}"


# --------------------------------------------------------------------------- #
# Directory scanning
# --------------------------------------------------------------------------- #


def _rel(path: Path, root: Path) -> str:
    return PurePosixPath(path.relative_to(root)).as_posix()


def iter_files(root: Path) -> Iterator[Path]:
    """Yield regular files under *root*, skipping the snapshot store and symlinks."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not (Path(dirpath) == root and d == STORE_DIR))
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            yield p


@dataclass
class Scan:
    by_fp: dict[str, list[str]] = field(default_factory=dict)  # fingerprint -> rel paths
    unreadable: list[str] = field(default_factory=list)

    @property
    def path_to_fp(self) -> dict[str, str]:
        return {p: fp for fp, paths in self.by_fp.items() for p in paths}


def scan(root: Path) -> Scan:
    result = Scan()
    for p in iter_files(root):
        rel = _rel(p, root)
        try:
            fp = fingerprint(p)
        except OSError:
            result.unreadable.append(rel)
            continue
        result.by_fp.setdefault(fp, []).append(rel)
    return result


# --------------------------------------------------------------------------- #
# Snapshots
# --------------------------------------------------------------------------- #


@dataclass
class Snapshot:
    id: str
    created: str
    description: str
    files: dict[str, str]  # fingerprint -> relative path
    skipped_duplicates: dict[str, list[str]] = field(default_factory=dict)
    unreadable: list[str] = field(default_factory=list)
    root: str = ""

    def to_json(self) -> dict:
        return {
            "format_version": FORMAT_VERSION,
            "fingerprint_scheme": FINGERPRINT_SCHEME,
            "id": self.id,
            "created": self.created,
            "description": self.description,
            "root": self.root,
            "files": dict(sorted(self.files.items(), key=lambda kv: kv[1])),
            "skipped_duplicates": self.skipped_duplicates,
            "unreadable": self.unreadable,
        }

    @classmethod
    def from_json(cls, data: object) -> Snapshot:
        if not isinstance(data, dict):
            raise DirlocError("snapshot must be a JSON object")
        if data.get("format_version") != FORMAT_VERSION:
            raise DirlocError(f"unsupported snapshot format: {data.get('format_version')!r}")
        if data.get("fingerprint_scheme") != FINGERPRINT_SCHEME:
            raise DirlocError(f"unsupported fingerprint scheme: {data.get('fingerprint_scheme')!r}")
        files = data["files"]
        if not isinstance(files, dict):
            raise DirlocError("snapshot 'files' must be an object")
        for rel in files.values():
            validate_rel_path(rel)
        dups = data.get("skipped_duplicates", {})
        if not isinstance(dups, dict) or not all(isinstance(v, list) for v in dups.values()):
            raise DirlocError("snapshot 'skipped_duplicates' must be an object of lists")
        for paths in dups.values():
            for rel in paths:
                validate_rel_path(rel)
        return cls(
            id=validate_snapshot_name(str(data["id"])),
            created=str(data["created"]),
            description=str(data.get("description", "")),
            files=files,
            skipped_duplicates=dups,
            unreadable=data.get("unreadable", []),
            root=data.get("root", ""),
        )


def store_dir(root: Path) -> Path:
    return root / STORE_DIR


def _new_id() -> str:
    stamp = _dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(2)}"


def save_snapshot(root: Path, description: str = "", name: str | None = None) -> tuple[Snapshot, Path]:
    snap_id = validate_snapshot_name(name) if name is not None else _new_id()
    sc = scan(root)
    files: dict[str, str] = {}
    dups: dict[str, list[str]] = {}
    for fp, paths in sc.by_fp.items():
        if len(paths) == 1:
            files[fp] = paths[0]
        else:
            dups[fp] = paths
    snap = Snapshot(
        id=snap_id,
        created=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="microseconds"),
        description=description,
        files=files,
        skipped_duplicates=dups,
        unreadable=sc.unreadable,
        root=str(root),
    )
    sdir = store_dir(root)
    sdir.mkdir(exist_ok=True)
    out = sdir / f"{snap.id}.json"
    try:
        fh = out.open("x", encoding="utf-8")
    except FileExistsError:
        raise DirlocError(f"snapshot {snap.id!r} already exists") from None
    try:
        with fh:
            fh.write(json.dumps(snap.to_json(), indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    return snap, out


def list_snapshots(root: Path) -> list[Snapshot]:
    sdir = store_dir(root)
    if not sdir.is_dir():
        return []
    snaps = []
    for f in sorted(sdir.glob("*.json")):
        try:
            snap = Snapshot.from_json(json.loads(f.read_text()))
            if snap.id != f.stem:
                raise DirlocError(f"snapshot id {snap.id!r} does not match filename")
            snaps.append(snap)
        except (OSError, ValueError, KeyError, TypeError, DirlocError) as e:
            print(f"warning: skipping unreadable snapshot {f.name}: {e}", file=sys.stderr)
    snaps.sort(key=lambda s: (s.created, s.id))
    return snaps


def find_snapshot(root: Path, ref: str) -> Snapshot:
    """Resolve *ref* (``latest``, exact id, unique id prefix, or description substring)."""
    snaps = list_snapshots(root)
    if not snaps:
        raise DirlocError(f"no snapshots found in {store_dir(root)}")
    if ref == "latest":
        return snaps[-1]
    exact = [s for s in snaps if s.id == ref]
    if exact:
        return exact[0]
    prefix = [s for s in snaps if s.id.startswith(ref)]
    if len(prefix) == 1:
        return prefix[0]
    if len(prefix) > 1:
        raise DirlocError(f"ambiguous snapshot ref {ref!r}: " + ", ".join(s.id for s in prefix))
    desc = [s for s in snaps if ref.lower() in s.description.lower()]
    if len(desc) == 1:
        return desc[0]
    if len(desc) > 1:
        raise DirlocError(f"ambiguous snapshot ref {ref!r} matches descriptions of: " + ", ".join(s.id for s in desc))
    raise DirlocError(f"no snapshot matching {ref!r}")


def delete_snapshot(root: Path, snap: Snapshot) -> Path:
    p = store_dir(root) / f"{snap.id}.json"
    p.unlink()
    return p


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #


@dataclass
class Plan:
    moves: list[tuple[str, str]] = field(default_factory=list)  # (current, target)
    unchanged: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # saved paths whose content is gone
    unsorted: list[tuple[str, str]] = field(default_factory=list)  # (current, _unsorted target)
    ambiguous: list[str] = field(default_factory=list)  # content that was duplicated at save time
    unreadable: list[str] = field(default_factory=list)

    @property
    def is_noop(self) -> bool:
        return not self.moves and not self.unsorted


def _suffixed(name: str, n: int) -> str:
    p = PurePosixPath(name)
    return f"{p.stem}~{n}{p.suffix}"


def _unsorted_target(rel: str, taken: set[str]) -> str:
    """Pick ``_unsorted/<rel>``, adding ``~N`` suffixes until it clashes with nothing in *taken*.

    A clash is an equal path, or one path being an ancestor of the other (a
    file cannot share a name with a directory). The clashing component is the
    one that gets suffixed, so ``_unsorted/x`` (existing file) + new ``x/y``
    yields ``_unsorted/x~1/y``.
    """
    parts = list(PurePosixPath(f"{UNSORTED_DIR}/{rel}").parts)
    counters = [0] * len(parts)
    while True:
        candidate = "/".join(parts)
        clash = next(
            (t for t in taken if t == candidate or t.startswith(candidate + "/") or candidate.startswith(t + "/")),
            None,
        )
        if clash is None:
            return candidate
        depth = min(len(PurePosixPath(clash).parts), len(parts)) - 1
        counters[depth] += 1
        original = PurePosixPath(f"{UNSORTED_DIR}/{rel}").parts[depth]
        parts[depth] = _suffixed(original, counters[depth])


def build_plan(root: Path, snap: Snapshot) -> Plan:
    sc = scan(root)
    plan = Plan(unreadable=sc.unreadable)
    claimed: set[str] = set()
    leftovers: list[str] = []

    for fp, target in sorted(snap.files.items(), key=lambda kv: kv[1]):
        current = sc.by_fp.get(fp)
        if not current:
            plan.missing.append(target)
            continue
        # Prefer a copy already sitting at the target path; otherwise the first (sorted) one.
        src = target if target in current else current[0]
        if src == target:
            plan.unchanged.append(target)
        else:
            plan.moves.append((src, target))
        claimed.add(src)
        leftovers.extend(p for p in current if p != src)

    # Content that was duplicated when the snapshot was taken has no single
    # saved location, so leave every copy where it is.
    for fp in snap.skipped_duplicates:
        for rel in sc.by_fp.get(fp, []):
            plan.ambiguous.append(rel)
            claimed.add(rel)

    unknown = [p for p in sc.path_to_fp if p not in claimed and p not in leftovers]
    taken = set(snap.files.values()) | set(plan.ambiguous)
    to_unsort: list[str] = []
    for rel in sorted(leftovers + unknown):
        if rel.startswith(UNSORTED_DIR + "/") and rel not in taken:
            plan.unchanged.append(rel)
            taken.add(rel)
        else:
            to_unsort.append(rel)
    for rel in to_unsort:
        dest = _unsorted_target(rel, taken)
        taken.add(dest)
        plan.unsorted.append((rel, dest))
    return plan


# --------------------------------------------------------------------------- #
# Applying a plan
# --------------------------------------------------------------------------- #


def _ancestors(base: Path, rel: str) -> Iterator[Path]:
    parts = PurePosixPath(rel).parts[:-1]
    for i in range(1, len(parts) + 1):
        yield base.joinpath(*parts[:i])


def _check_targets(base: Path, targets: list[str], vacating: set[str]) -> None:
    """Raise unless every target path can be created without clobbering anything.

    *vacating* holds relative paths (under *base*) that will have been moved
    away before targets are written; a target may be a file that is being
    moved, or a directory whose only contents are being moved.
    """
    for dst in targets:
        for anc in _ancestors(base, dst):
            if anc.is_symlink():
                raise DirlocError(f"cannot restore {dst}: {anc.relative_to(base)} is a symlink")
            if anc.exists() and not anc.is_dir() and _rel(anc, base) not in vacating:
                raise DirlocError(f"cannot restore {dst}: {anc.relative_to(base)} is not a directory")
        final = base / dst
        if not final.exists() and not final.is_symlink():
            continue
        if final.is_symlink() or final.is_file():
            if dst not in vacating:
                raise DirlocError(f"cannot restore {dst}: target already exists")
            continue
        if final.is_dir():
            for dirpath, dirnames, filenames in os.walk(final):
                for name in dirnames + filenames:
                    p = Path(dirpath) / name
                    if p.is_symlink() or (p.is_file() and _rel(p, base) not in vacating):
                        raise DirlocError(f"cannot restore {dst}: directory is not empty ({_rel(p, base)})")
            continue
        raise DirlocError(f"cannot restore {dst}: target already exists")


def _mkdir_tracking(d: Path, created: list[Path]) -> None:
    """``mkdir -p`` that appends each directory to *created* as soon as it exists."""
    missing: list[Path] = []
    while not d.exists():
        missing.append(d)
        d = d.parent
    for p in reversed(missing):
        p.mkdir()
        created.append(p)


def _remove_empty_tree(d: Path) -> list[Path]:
    """Remove *d* and its (empty) subdirectories; return what was removed, deepest first."""
    removed: list[Path] = []
    for dirpath, _dirnames, _filenames in os.walk(d, topdown=False):
        Path(dirpath).rmdir()
        removed.append(Path(dirpath))
    return removed


def _prune_empty_dirs(root: Path, dirs: set[Path]) -> None:
    for d in sorted(dirs, key=lambda p: len(p.parts), reverse=True):
        while d != root and d.is_dir() and d.name != STORE_DIR:
            try:
                d.rmdir()
            except OSError:
                break
            d = d.parent


def apply_in_place(root: Path, plan: Plan, snap_id: str) -> None:
    """Move files within *root*.

    Conflicts are detected before anything is touched. Files then go through a
    staging directory (so swaps and chains are safe); if anything fails
    midway, every move is undone. Should the undo itself fail, nothing is
    deleted: whatever is still in the staging directory is left there and its
    path is reported.
    """
    all_moves = plan.moves + plan.unsorted
    if not all_moves:
        return
    sources = {src for src, _ in all_moves}
    _check_targets(root, [dst for _, dst in all_moves], sources)

    staging = store_dir(root) / f"{STAGING_PREFIX}{snap_id}-{secrets.token_hex(3)}"
    staging.mkdir(parents=True)
    vacated: set[Path] = set()
    staged: list[tuple[str, Path]] = []  # (src, tmp)
    installed: list[tuple[Path, Path]] = []  # (final, tmp)
    removed_dirs: list[Path] = []
    created_dirs: list[Path] = []
    try:
        for i, (src, _dst) in enumerate(all_moves):
            tmp = staging / str(i)
            os.replace(root / src, tmp)
            staged.append((src, tmp))
            vacated.add((root / src).parent)
        for (_src, tmp), (_s, dst) in zip(staged, all_moves):
            final = root / dst
            if final.is_dir() and not final.is_symlink():
                removed_dirs.extend(_remove_empty_tree(final))
            elif final.exists() or final.is_symlink():
                raise DirlocError(f"cannot restore {dst}: target already exists")
            _mkdir_tracking(final.parent, created_dirs)
            os.replace(tmp, final)
            installed.append((final, tmp))
    except Exception as exc:
        try:
            for final, tmp in reversed(installed):
                os.replace(final, tmp)
            for d in reversed(created_dirs):
                d.rmdir()
            for d in reversed(removed_dirs):
                d.mkdir(exist_ok=True)
            for src, tmp in staged:
                if tmp.exists():
                    (root / src).parent.mkdir(parents=True, exist_ok=True)
                    os.replace(tmp, root / src)
        except OSError as undo_exc:
            raise DirlocError(
                f"restore failed ({exc}) and rolling back also failed ({undo_exc}); "
                f"files still in transit were left under {staging}"
            ) from exc
        raise
    finally:
        with contextlib.suppress(OSError):
            staging.rmdir()
    _prune_empty_dirs(root, vacated)


def apply_to_output(root: Path, plan: Plan, out: Path) -> None:
    """Copy files into *out* at their saved paths, leaving *root* untouched."""
    if out.resolve() == root.resolve() or root.resolve() in out.resolve().parents:
        raise DirlocError("--output-dir must not be the source dir or inside it")
    copies = plan.moves + [(p, p) for p in plan.unchanged + plan.ambiguous] + plan.unsorted
    out.mkdir(parents=True, exist_ok=True)
    _check_targets(out, [dst for _, dst in copies], set())
    for src, dst in copies:
        final = out / dst
        if final.is_dir():
            _remove_empty_tree(final)
        final.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / src, final)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _root(arg: str) -> Path:
    root = Path(arg).expanduser().resolve()
    if not root.is_dir():
        raise DirlocError(f"not a directory: {arg}")
    return root


def _print_plan(plan: Plan, verb: str) -> None:
    for src, dst in plan.moves:
        print(f"{verb} {src} -> {dst}")
    for src, dst in plan.unsorted:
        print(f"{verb} {src} -> {dst}  (not in snapshot)")
    for p in plan.missing:
        print(f"missing {p}")
    for p in plan.ambiguous:
        print(f"keep {p}  (duplicate content at save time)")
    for p in plan.unreadable:
        print(f"unreadable {p}")
    print(
        f"{len(plan.moves)} to move, {len(plan.unsorted)} to _unsorted, "
        f"{len(plan.unchanged)} unchanged, {len(plan.missing)} missing"
    )


def cmd_save(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    snap, path = save_snapshot(root, description=args.description or "", name=args.name)
    print(f"saved snapshot {snap.id} ({len(snap.files)} files) -> {path}")
    if snap.description:
        print(f"  description: {snap.description}")
    for fp, paths in snap.skipped_duplicates.items():
        print(f"warning: skipped {len(paths)} files with identical content [{fp}]:", file=sys.stderr)
        for p in paths:
            print(f"    {p}", file=sys.stderr)
    for p in snap.unreadable:
        print(f"warning: unreadable, skipped: {p}", file=sys.stderr)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    snaps = list_snapshots(root)
    if not snaps:
        print(f"no snapshots in {store_dir(root)}")
        return 0
    width = max(len(s.id) for s in snaps)
    for s in snaps:
        print(f"{s.id:<{width}}  {s.created}  {len(s.files):>6} files  {s.description}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    snap = find_snapshot(root, args.snapshot)
    print(f"id:          {snap.id}")
    print(f"created:     {snap.created}")
    print(f"description: {snap.description}")
    print(f"root:        {snap.root}")
    print(f"files:       {len(snap.files)}")
    for fp, p in sorted(snap.files.items(), key=lambda kv: kv[1]):
        print(f"  {fp}  {p}")
    if snap.skipped_duplicates:
        print("skipped duplicates:")
        for fp, paths in snap.skipped_duplicates.items():
            print(f"  {fp}  " + ", ".join(paths))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    snap = find_snapshot(root, args.snapshot)
    plan = build_plan(root, snap)
    _print_plan(plan, "move")
    return 0 if plan.is_noop and not plan.missing and not plan.unreadable else 1


def cmd_restore(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    snap = find_snapshot(root, args.snapshot)
    plan = build_plan(root, snap)
    if args.output_dir:
        out = Path(args.output_dir).expanduser()
        _print_plan(plan, "copy" if not args.dry_run else "would copy")
        if not args.dry_run:
            apply_to_output(root, plan, out)
            print(f"restored snapshot {snap.id} into {out}")
        return 0
    _print_plan(plan, "move" if not args.dry_run else "would move")
    if args.dry_run:
        return 0
    if plan.is_noop:
        print("nothing to do")
        return 0
    apply_in_place(root, plan, snap.id)
    print(f"restored snapshot {snap.id} in place")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    snap = find_snapshot(root, args.snapshot)
    path = delete_snapshot(root, snap)
    print(f"deleted snapshot {snap.id} ({path})")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    for f in args.files:
        print(f"{fingerprint(Path(f))}  {f}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dirloc", description=__doc__.split("\n\n")[0])
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, func, help: str, snapshot: bool = False) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help)
        sp.add_argument("dir", nargs="?", default=".", help="directory (default: .)")
        if snapshot:
            sp.add_argument(
                "-s",
                "--snapshot",
                default="latest",
                help="snapshot id, unique id prefix, description substring, or 'latest' (default)",
            )
        sp.set_defaults(func=func)
        return sp

    sp = add("save", cmd_save, "record the current layout of DIR")
    sp.add_argument("-d", "--description", help="free-text description stored with the snapshot")
    sp.add_argument("-n", "--name", help="use NAME as the snapshot id instead of a timestamp")

    add("list", cmd_list, "list snapshots of DIR")
    add("show", cmd_show, "print a snapshot's contents", snapshot=True)
    add("diff", cmd_diff, "show what restore would do (exit 1 if anything differs or could not be read)", snapshot=True)

    sp = add("restore", cmd_restore, "put files back at their saved paths", snapshot=True)
    sp.add_argument("--dry-run", action="store_true", help="only print the plan")
    sp.add_argument("-o", "--output-dir", help="copy into this dir instead of moving in place")

    add("delete", cmd_delete, "delete a snapshot", snapshot=True)

    sp = sub.add_parser("fingerprint", help="print fingerprints of the given files")
    sp.add_argument("files", nargs="+")
    sp.set_defaults(func=cmd_fingerprint)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DirlocError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
