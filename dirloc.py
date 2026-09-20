#!/usr/bin/env python3
"""dirloc - save and restore the layout (paths + filenames) of a directory.

Files are identified by a content fingerprint (size + hash of head/middle/tail
chunks), so they can be renamed or moved around freely and later put back where
they were when a snapshot was taken.

Snapshots are stored as JSON files under ``<dir>/.dirloc/``.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
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


class DirlocError(Exception):
    pass


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
    def from_json(cls, data: dict) -> Snapshot:
        if data.get("format_version") != FORMAT_VERSION:
            raise DirlocError(f"unsupported snapshot format: {data.get('format_version')!r}")
        return cls(
            id=data["id"],
            created=data["created"],
            description=data.get("description", ""),
            files=data["files"],
            skipped_duplicates=data.get("skipped_duplicates", {}),
            unreadable=data.get("unreadable", []),
            root=data.get("root", ""),
        )


def store_dir(root: Path) -> Path:
    return root / STORE_DIR


def _new_id() -> str:
    stamp = _dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(2)}"


def save_snapshot(root: Path, description: str = "", name: str | None = None) -> tuple[Snapshot, Path]:
    sc = scan(root)
    files: dict[str, str] = {}
    dups: dict[str, list[str]] = {}
    for fp, paths in sc.by_fp.items():
        if len(paths) == 1:
            files[fp] = paths[0]
        else:
            dups[fp] = paths
    snap = Snapshot(
        id=name or _new_id(),
        created=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        description=description,
        files=files,
        skipped_duplicates=dups,
        unreadable=sc.unreadable,
        root=str(root),
    )
    if "/" in snap.id or snap.id in ("", ".", "..", "latest"):
        raise DirlocError(f"invalid snapshot name: {snap.id!r}")
    sdir = store_dir(root)
    sdir.mkdir(exist_ok=True)
    out = sdir / f"{snap.id}.json"
    if out.exists():
        raise DirlocError(f"snapshot {snap.id!r} already exists")
    out.write_text(json.dumps(snap.to_json(), indent=2) + "\n")
    return snap, out


def list_snapshots(root: Path) -> list[Snapshot]:
    sdir = store_dir(root)
    if not sdir.is_dir():
        return []
    snaps = []
    for f in sorted(sdir.glob("*.json")):
        try:
            snaps.append(Snapshot.from_json(json.loads(f.read_text())))
        except (OSError, ValueError, KeyError, DirlocError) as e:
            print(f"warning: skipping unreadable snapshot {f.name}: {e}", file=sys.stderr)
    snaps.sort(key=lambda s: s.created)
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
    unreadable: list[str] = field(default_factory=list)

    @property
    def is_noop(self) -> bool:
        return not self.moves and not self.unsorted


def _unsorted_target(rel: str, taken: set[str]) -> str:
    base = f"{UNSORTED_DIR}/{rel}"
    candidate = base
    n = 1
    while candidate in taken:
        p = PurePosixPath(base)
        candidate = str(p.with_name(f"{p.stem}~{n}{p.suffix}"))
        n += 1
    return candidate


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

    unknown = [p for p in sc.path_to_fp if p not in claimed and p not in leftovers]
    taken = set(snap.files.values())
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


def _prune_empty_dirs(root: Path, dirs: set[Path]) -> None:
    for d in sorted(dirs, key=lambda p: len(p.parts), reverse=True):
        while d != root and d.is_dir() and d.name != STORE_DIR:
            try:
                d.rmdir()
            except OSError:
                break
            d = d.parent


def apply_in_place(root: Path, plan: Plan, snap_id: str) -> None:
    """Move files within *root*; a two-phase move through a staging dir avoids collisions."""
    all_moves = plan.moves + plan.unsorted
    if not all_moves:
        return
    staging = store_dir(root) / f"{STAGING_PREFIX}{snap_id}-{secrets.token_hex(3)}"
    staging.mkdir(parents=True)
    vacated: set[Path] = set()
    try:
        staged: list[tuple[Path, str]] = []
        for i, (src, dst) in enumerate(all_moves):
            tmp = staging / str(i)
            os.replace(root / src, tmp)
            vacated.add((root / src).parent)
            staged.append((tmp, dst))
        for tmp, dst in staged:
            final = root / dst
            if final.exists():
                raise DirlocError(f"target already exists: {dst}")
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, final)
    except Exception:
        # Best effort: put anything still staged back where it came from.
        for i, (src, _dst) in enumerate(all_moves):
            tmp = staging / str(i)
            if tmp.exists():
                (root / src).parent.mkdir(parents=True, exist_ok=True)
                os.replace(tmp, root / src)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    _prune_empty_dirs(root, vacated)


def apply_to_output(root: Path, plan: Plan, out: Path) -> None:
    """Copy files into *out* at their saved paths, leaving *root* untouched."""
    if out.resolve() == root.resolve() or root.resolve() in out.resolve().parents:
        raise DirlocError("--output-dir must not be the source dir or inside it")
    out.mkdir(parents=True, exist_ok=True)
    for src, dst in plan.moves + [(p, p) for p in plan.unchanged] + plan.unsorted:
        final = out / dst
        if final.exists():
            raise DirlocError(f"target already exists: {final}")
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
    return 0 if plan.is_noop and not plan.missing else 1


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
    add("diff", cmd_diff, "show what restore would do (exit 1 if anything differs)", snapshot=True)

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
