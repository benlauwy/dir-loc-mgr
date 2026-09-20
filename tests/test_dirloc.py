import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dirloc


def write(root: Path, rel: str, data: bytes | str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    p.write_bytes(data)
    return p


def files_under(root: Path) -> set[str]:
    return {
        dirloc._rel(p, root)
        for p in root.rglob("*")
        if p.is_file() and dirloc.STORE_DIR not in p.relative_to(root).parts
    }


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_small_file_full_hash(self):
        a = write(self.tmp, "a", "hello")
        b = write(self.tmp, "b", "hello")
        c = write(self.tmp, "c", "hellp")
        self.assertEqual(dirloc.fingerprint(a), dirloc.fingerprint(b))
        self.assertNotEqual(dirloc.fingerprint(a), dirloc.fingerprint(c))
        self.assertTrue(dirloc.fingerprint(a).startswith("5:"))

    def test_large_file_samples_head_mid_tail(self):
        size = 10 * dirloc.CHUNK_SIZE
        data = bytearray(os.urandom(size))
        a = write(self.tmp, "a", bytes(data))
        fp_a = dirloc.fingerprint(a)
        self.assertTrue(fp_a.startswith(f"{size}:"))
        # Same file again -> same fingerprint.
        self.assertEqual(fp_a, dirloc.fingerprint(write(self.tmp, "a2", bytes(data))))
        # Changes in head, middle and tail all change the fingerprint.
        for offset in (0, size // 2, size - 1):
            mutated = bytearray(data)
            mutated[offset] ^= 0xFF
            self.assertNotEqual(fp_a, dirloc.fingerprint(write(self.tmp, "m", bytes(mutated))))
        # A change outside the sampled regions is (by design) not detected.
        mutated = bytearray(data)
        mutated[2 * dirloc.CHUNK_SIZE] ^= 0xFF
        self.assertEqual(fp_a, dirloc.fingerprint(write(self.tmp, "m2", bytes(mutated))))


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        write(self.root, "a/one.txt", "one")
        write(self.root, "a/b/two.txt", "two")
        write(self.root, "c/three.txt", "three")
        write(self.root, "big.bin", os.urandom(5 * dirloc.CHUNK_SIZE))

    def tearDown(self):
        shutil.rmtree(self.root)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = dirloc.main([*argv])
        return code, out.getvalue(), err.getvalue()

    def test_save_and_list_with_description(self):
        snap, path = dirloc.save_snapshot(self.root, description="before reorg")
        self.assertTrue(path.exists())
        self.assertEqual(path.parent, self.root / dirloc.STORE_DIR)
        self.assertEqual(set(snap.files.values()), {"a/one.txt", "a/b/two.txt", "c/three.txt", "big.bin"})
        snaps = dirloc.list_snapshots(self.root)
        self.assertEqual([s.id for s in snaps], [snap.id])
        self.assertEqual(snaps[0].description, "before reorg")
        code, out, _ = self.run_cli("list", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("before reorg", out)

    def test_save_skips_store_dir_and_symlinks(self):
        dirloc.save_snapshot(self.root)
        os.symlink(self.root / "a/one.txt", self.root / "link.txt")
        snap, _ = dirloc.save_snapshot(self.root)
        self.assertNotIn("link.txt", snap.files.values())
        self.assertFalse(any(p.startswith(dirloc.STORE_DIR) for p in snap.files.values()))

    def test_duplicates_are_skipped_with_warning(self):
        write(self.root, "d1.txt", "dup")
        write(self.root, "x/d2.txt", "dup")
        code, _, err = self.run_cli("save", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("identical content", err)
        snap = dirloc.list_snapshots(self.root)[0]
        self.assertNotIn("d1.txt", snap.files.values())
        self.assertNotIn("x/d2.txt", snap.files.values())
        self.assertEqual(sorted(next(iter(snap.skipped_duplicates.values()))), ["d1.txt", "x/d2.txt"])

    def test_find_snapshot_by_id_prefix_description_and_latest(self):
        s1, _ = dirloc.save_snapshot(self.root, description="alpha layout", name="first")
        s2, _ = dirloc.save_snapshot(self.root, description="beta layout", name="second")
        self.assertEqual(dirloc.find_snapshot(self.root, "first").id, s1.id)
        self.assertEqual(dirloc.find_snapshot(self.root, "sec").id, s2.id)
        self.assertEqual(dirloc.find_snapshot(self.root, "alpha").id, s1.id)
        self.assertEqual(dirloc.find_snapshot(self.root, "latest").id, s2.id)
        with self.assertRaises(dirloc.DirlocError):
            dirloc.find_snapshot(self.root, "layout")  # ambiguous description
        with self.assertRaises(dirloc.DirlocError):
            dirloc.find_snapshot(self.root, "nope")
        with self.assertRaises(dirloc.DirlocError):
            dirloc.save_snapshot(self.root, name="first")  # already exists

    def test_restore_in_place(self):
        snap, _ = dirloc.save_snapshot(self.root)
        before = files_under(self.root)
        (self.root / "a/one.txt").rename(self.root / "c/renamed.txt")
        (self.root / "a/b/two.txt").rename(self.root / "two.txt")
        (self.root / "big.bin").rename(self.root / "a/b/big2.bin")
        write(self.root, "newfile.txt", "new")
        (self.root / "c/three.txt").unlink()

        plan = dirloc.build_plan(self.root, snap)
        self.assertEqual(
            sorted(plan.moves),
            [
                ("a/b/big2.bin", "big.bin"),
                ("c/renamed.txt", "a/one.txt"),
                ("two.txt", "a/b/two.txt"),
            ],
        )
        self.assertEqual(plan.missing, ["c/three.txt"])
        self.assertEqual(plan.unsorted, [("newfile.txt", "_unsorted/newfile.txt")])

        dirloc.apply_in_place(self.root, plan, snap.id)
        self.assertEqual(files_under(self.root), (before - {"c/three.txt"}) | {"_unsorted/newfile.txt"})
        self.assertEqual((self.root / "a/one.txt").read_text(), "one")
        self.assertFalse((self.root / "c").exists())  # vacated dir pruned
        self.assertEqual(list((self.root / dirloc.STORE_DIR).glob("staging-*")), [])
        # Second restore is a no-op.
        self.assertTrue(dirloc.build_plan(self.root, snap).is_noop)

    def test_restore_handles_swaps(self):
        snap, _ = dirloc.save_snapshot(self.root)
        os.replace(self.root / "a/one.txt", self.root / "tmp")
        os.replace(self.root / "a/b/two.txt", self.root / "a/one.txt")
        os.replace(self.root / "tmp", self.root / "a/b/two.txt")
        plan = dirloc.build_plan(self.root, snap)
        self.assertEqual(len(plan.moves), 2)
        dirloc.apply_in_place(self.root, plan, snap.id)
        self.assertEqual((self.root / "a/one.txt").read_text(), "one")
        self.assertEqual((self.root / "a/b/two.txt").read_text(), "two")

    def test_restore_duplicates_at_restore_time_go_to_unsorted(self):
        snap, _ = dirloc.save_snapshot(self.root)
        shutil.copy(self.root / "a/one.txt", self.root / "copy.txt")
        plan = dirloc.build_plan(self.root, snap)
        self.assertEqual(plan.moves, [])
        self.assertEqual(plan.unsorted, [("copy.txt", "_unsorted/copy.txt")])

    def test_unsorted_name_collisions(self):
        snap, _ = dirloc.save_snapshot(self.root)
        write(self.root, "_unsorted/x.txt", "old unsorted")
        write(self.root, "x.txt", "new x")
        plan = dirloc.build_plan(self.root, snap)
        self.assertIn("_unsorted/x.txt", plan.unchanged)
        self.assertEqual(plan.unsorted, [("x.txt", "_unsorted/x~1.txt")])
        dirloc.apply_in_place(self.root, plan, snap.id)
        self.assertEqual((self.root / "_unsorted/x.txt").read_text(), "old unsorted")
        self.assertEqual((self.root / "_unsorted/x~1.txt").read_text(), "new x")

    def test_restore_to_output_dir(self):
        snap, _ = dirloc.save_snapshot(self.root)
        (self.root / "a/one.txt").rename(self.root / "moved.txt")
        write(self.root, "extra.txt", "extra")
        before = files_under(self.root)
        out = Path(tempfile.mkdtemp()) / "out"
        try:
            code, _, _ = self.run_cli("restore", str(self.root), "-o", str(out))
            self.assertEqual(code, 0)
            self.assertEqual(files_under(self.root), before)  # source untouched
            self.assertEqual(
                files_under(out),
                {"a/one.txt", "a/b/two.txt", "c/three.txt", "big.bin", "_unsorted/extra.txt"},
            )
            self.assertEqual((out / "a/one.txt").read_text(), "one")
        finally:
            shutil.rmtree(out.parent)
        with self.assertRaises(dirloc.DirlocError):
            dirloc.apply_to_output(self.root, dirloc.build_plan(self.root, snap), self.root / "sub")

    def test_diff_and_dry_run_do_not_touch_files(self):
        dirloc.save_snapshot(self.root, name="s")
        (self.root / "a/one.txt").rename(self.root / "moved.txt")
        before = files_under(self.root)
        code, out, _ = self.run_cli("diff", str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("move moved.txt -> a/one.txt", out)
        code, out, _ = self.run_cli("restore", str(self.root), "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("would move moved.txt -> a/one.txt", out)
        self.assertEqual(files_under(self.root), before)
        code, _, _ = self.run_cli("restore", str(self.root), "-s", "s")
        self.assertEqual(code, 0)
        code, _, _ = self.run_cli("diff", str(self.root))
        self.assertEqual(code, 0)

    def test_delete_and_show(self):
        dirloc.save_snapshot(self.root, name="keep", description="keep me")
        dirloc.save_snapshot(self.root, name="drop")
        code, out, _ = self.run_cli("show", str(self.root), "-s", "keep")
        self.assertEqual(code, 0)
        self.assertIn("keep me", out)
        self.assertIn("a/b/two.txt", out)
        code, _, _ = self.run_cli("delete", str(self.root), "-s", "drop")
        self.assertEqual(code, 0)
        self.assertEqual([s.id for s in dirloc.list_snapshots(self.root)], ["keep"])

    def test_errors_exit_2(self):
        code, _, err = self.run_cli("restore", str(self.root))
        self.assertEqual(code, 2)
        self.assertIn("no snapshots", err)
        code, _, err = self.run_cli("list", str(self.root / "nope"))
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)


if __name__ == "__main__":
    unittest.main()
