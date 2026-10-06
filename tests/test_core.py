"""Acceptance tests for the Merkle hash tree kernel."""

import unittest

from merkle.core import MerkleTree, verify_proof


class TaggedHasher:
    """Readable stand-in for the default hasher; keeps the digests short."""

    def leaf(self, data):
        return "L:" + bytes(data).decode("ascii")

    def node(self, left, right):
        return "N(" + left + "|" + right + ")"


HASH = TaggedHasher()


def tree(*leaves):
    return MerkleTree(leaves, hasher=HASH)


class SingleLeafTests(unittest.TestCase):

    def test_single_leaf_root_is_the_leaf_digest(self):
        one = tree(b"a")
        self.assertEqual(len(one), 1)
        self.assertEqual(one.height(), 1)
        self.assertEqual(one.levels(), (("L:a",),))
        self.assertEqual(one.root, "L:a")
        self.assertEqual(one.proof(0), ())
        self.assertTrue(one.verify(0, b"a", ()))
        self.assertFalse(one.verify(1, b"a", ()))


class LevelFoldingTests(unittest.TestCase):

    def test_even_levels_fold_neighbours_pairwise(self):
        four = tree(b"a", b"b", b"c", b"d")
        self.assertEqual(four.height(), 3)
        self.assertEqual([len(level) for level in four.levels()], [4, 2, 1])
        self.assertEqual(four.levels()[1], ("N(L:a|L:b)", "N(L:c|L:d)"))
        self.assertEqual(four.root, "N(N(L:a|L:b)|N(L:c|L:d))")
        plain = MerkleTree([b"a", b"b"]).root
        self.assertEqual(len(plain), 64)
        self.assertEqual(plain, plain.lower())

    def test_odd_level_promotes_the_lone_node(self):
        three = tree(b"a", b"b", b"c")
        self.assertEqual([len(level) for level in three.levels()], [3, 2, 1])
        self.assertEqual(three.levels()[1], ("N(L:a|L:b)", "L:c"))
        self.assertEqual(three.root, "N(N(L:a|L:b)|L:c)")
        five = tree(b"a", b"b", b"c", b"d", b"e")
        self.assertEqual([len(level) for level in five.levels()],
                         [5, 3, 2, 1])
        self.assertEqual(five.levels()[2],
                         ("N(N(L:a|L:b)|N(L:c|L:d))", "L:e"))
        self.assertEqual(five.root, "N(N(N(L:a|L:b)|N(L:c|L:d))|L:e)")


class RebuildTests(unittest.TestCase):

    def test_append_and_update_rebuild_the_root(self):
        two = tree(b"a", b"b")
        before = two.root
        self.assertEqual(before, "N(L:a|L:b)")
        grown = two.append(b"c")
        self.assertEqual(len(two), 3)
        self.assertEqual(two.leaves(), (b"a", b"b", b"c"))
        self.assertEqual(grown, "N(N(L:a|L:b)|L:c)")
        self.assertNotEqual(two.root, before)
        replaced = two.update(0, b"z")
        self.assertEqual(replaced, "N(N(L:z|L:b)|L:c)")
        self.assertEqual(two.leaves(), (b"z", b"b", b"c"))
        self.assertEqual(two.root, "N(N(L:z|L:b)|L:c)")
        self.assertEqual(two.height(), 3)

    def test_update_rejects_out_of_range_and_negative_indices(self):
        two = tree(b"a", b"b")
        with self.assertRaises(IndexError):
            two.update(2, b"z")
        with self.assertRaises(IndexError):
            two.update(-1, b"z")
        self.assertEqual(two.leaves(), (b"a", b"b"))
        self.assertEqual(two.root, "N(L:a|L:b)")
        empty = MerkleTree([], hasher=HASH)
        with self.assertRaises(IndexError):
            empty.update(0, b"z")
        self.assertEqual(empty.leaves(), ())


class ProofTests(unittest.TestCase):

    def test_proof_layout_names_sides_and_order(self):
        four = tree(b"a", b"b", b"c", b"d")
        self.assertEqual(four.proof(0), (("right", "L:b"),
                                         ("right", "N(L:c|L:d)")))
        self.assertEqual(four.proof(3), (("left", "L:c"),
                                         ("left", "N(L:a|L:b)")))
        self.assertEqual([side for side, _ in four.proof(0)],
                         ["right", "right"])
        self.assertEqual([side for side, _ in four.proof(3)], ["left", "left"])
        self.assertEqual(four.proof(1), (("left", "L:a"),
                                         ("right", "N(L:c|L:d)")))
        self.assertEqual([side for side, _ in four.proof(2)],
                         ["right", "left"])
        three = tree(b"a", b"b", b"c")
        self.assertEqual(three.proof(2), (("left", "N(L:a|L:b)"),))

    def test_valid_proofs_verify_and_tampered_leaves_do_not(self):
        four = tree(b"a", b"b", b"c", b"d")
        self.assertEqual(four.root, "N(N(L:a|L:b)|N(L:c|L:d))")
        for index in range(4):
            leaf = four.leaves()[index]
            self.assertTrue(four.verify(index, leaf, four.proof(index)),
                            "a genuine proof did not verify")
            self.assertFalse(four.verify(index, leaf + b"!",
                                         four.proof(index)),
                             "a tampered leaf was accepted")
        self.assertFalse(four.verify(1, b"a", four.proof(0)),
                         "a proof was accepted for the wrong leaf")

    def test_proofs_verify_when_a_level_has_an_odd_width(self):
        three = tree(b"a", b"b", b"c")
        self.assertEqual(three.root, "N(N(L:a|L:b)|L:c)")
        five = tree(b"a", b"b", b"c", b"d", b"e")
        self.assertEqual(five.root, "N(N(N(L:a|L:b)|N(L:c|L:d))|L:e)")
        for index in range(3):
            leaf = three.leaves()[index]
            self.assertTrue(three.verify(index, leaf, three.proof(index)),
                            "a genuine proof did not verify")
        for index in range(5):
            leaf = five.leaves()[index]
            self.assertTrue(five.verify(index, leaf, five.proof(index)),
                            "a genuine proof did not verify")

    def test_malformed_proofs_are_rejected(self):
        root = "N(N(L:a|L:b)|N(L:c|L:d))"
        good = (("right", "L:b"), ("right", "N(L:c|L:d)"))
        self.assertTrue(verify_proof(root, 0, b"a", good, 4, HASH))
        self.assertFalse(verify_proof(root, 0, b"a",
                                      good + (("right", "L:x"),), 4, HASH),
                         "an extra step was ignored")
        self.assertFalse(verify_proof(root, 0, b"a", good[:-1], 4, HASH),
                         "a truncated proof was accepted")
        wrong_side = (("left", "L:b"), ("right", "N(L:c|L:d)"))
        self.assertFalse(verify_proof(root, 0, b"a", wrong_side, 4, HASH),
                         "a step on the wrong side was accepted")
        self.assertFalse(verify_proof(root, 0, b"a", (), 4, HASH))
        self.assertFalse(verify_proof(root, 4, b"a", good, 4, HASH))
        self.assertFalse(verify_proof(root, -1, b"a", good, 4, HASH))


class EmptyTreeTests(unittest.TestCase):

    def test_empty_tree_has_a_fixed_root_and_no_proofs(self):
        empty = MerkleTree([], hasher=HASH)
        self.assertEqual(len(empty), 0)
        self.assertEqual(empty.height(), 0)
        self.assertEqual(empty.levels(), ())
        self.assertFalse(verify_proof("L:", 0, b"a", (), 0, HASH))
        with self.assertRaises(IndexError):
            empty.proof(0)
        self.assertEqual(empty.root, "L:")
        self.assertEqual(MerkleTree([], hasher=HASH).root, empty.root)


if __name__ == "__main__":
    unittest.main()
