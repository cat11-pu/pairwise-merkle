"""Deterministic Merkle hash tree kernel.

A tree is built bottom up from an ordered list of byte-string leaves. Every
leaf is hashed on its own, and each level above it folds its nodes in
neighbouring pairs. A node that is left without a partner keeps its digest
and moves up to the next level as it is; the single digest left at the top
is the root.

The hash function is injected by the caller and only has to offer two
methods: leaf(data) for the leaf level and node(left, right) for everything
above it. The default is SHA-256 with the two levels domain separated, so a
leaf digest can never be read as an inner node digest. Nothing in this module
reads a clock, draws randomness or touches the outside world, so the same
leaves always produce the same root.

An inclusion proof is a tuple of (side, digest) steps ordered from the leaf
level upwards. side is "left" when the sibling digest sits to the left of the
running node and "right" when it sits to the right. A node that was promoted
without a partner contributes no step at that level.
"""

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class Sha256Hasher:
    """Default hash function: SHA-256 over domain separated inputs."""

    def leaf(self, data):
        """Digest of one leaf payload."""
        return hashlib.sha256(LEAF_PREFIX + bytes(data)).hexdigest()

    def node(self, left, right):
        """Digest of an inner node built from two child digests."""
        payload = left.encode("utf-8") + right.encode("utf-8")
        return hashlib.sha256(NODE_PREFIX + payload).hexdigest()


DEFAULT_HASHER = Sha256Hasher()


class MerkleTree:
    """Binary hash tree over byte-string leaves."""

    def __init__(self, leaves=(), hasher=None):
        self.hasher = hasher or DEFAULT_HASHER
        self._leaves = [bytes(leaf) for leaf in leaves]
        self._levels = None
        self._root = None

    # -- reading ---------------------------------------------------------
    def __len__(self):
        return len(self._leaves)

    def leaves(self):
        """The leaf payloads in tree order."""
        return tuple(self._leaves)

    def levels(self):
        """Every level from the leaves up; the root tops the last one."""
        if self._levels is None:
            self.rebuild()
        return tuple(tuple(level) for level in self._levels)

    def height(self):
        """How many levels the tree has; an empty tree has none."""
        return len(self.levels())

    @property
    def root(self):
        """The digest at the top of the tree."""
        if self._root is None:
            self.rebuild()
        return self._root

    # -- building --------------------------------------------------------
    def _leaf_level(self):
        """Hash every leaf payload on its own."""
        return [self.hasher.leaf(data) for data in self._leaves]

    def _fold(self, level):
        """Fold one level into the level above it."""
        width = len(level)
        folded = [self.hasher.node(level[index], level[index + 1])
                  for index in range(0, width - 1, 2)]
        if width % 2:
            folded.append(self.hasher.node(level[-1], level[-1]))
        return folded

    def rebuild(self):
        """Recompute every level from the current leaves; returns the root."""
        if not self._leaves:
            self._levels = []
            self._root = ""
            return self._root
        levels = [self._leaf_level()]
        while len(levels[-1]) > 1:
            levels.append(self._fold(levels[-1]))
        self._levels = levels
        self._root = levels[-1][0]
        return self._root

    def _drop_cache(self):
        """Forget the levels and the root after the leaves changed."""
        self._levels = None
        self._root = None

    # -- changing --------------------------------------------------------
    def append(self, leaf):
        """Add one leaf at the end; returns the new root."""
        self._leaves.append(bytes(leaf))
        return self.root

    def update(self, index, leaf):
        """Replace the leaf at index; returns the new root."""
        if index >= len(self._leaves):
            raise IndexError("leaf index out of range: %r" % (index,))
        self._leaves[index] = bytes(leaf)
        self._drop_cache()
        return self.root

    # -- proofs ----------------------------------------------------------
    def proof(self, index):
        """Inclusion proof for one leaf, leaf level first."""
        if not 0 <= index < len(self._leaves):
            raise IndexError("leaf index out of range: %r" % (index,))
        if self._levels is None:
            self.rebuild()
        steps = []
        position = index
        for level in self._levels[:-1]:
            if position % 2 == 0:
                sibling = position + 1
                if sibling < len(level):
                    steps.append(("left", level[sibling]))
            else:
                steps.append(("right", level[position - 1]))
            position //= 2
        return tuple(reversed(steps))

    def verify(self, index, leaf, proof):
        """Check one proof against this tree."""
        return verify_proof(self.root, index, leaf, proof,
                            len(self._leaves), self.hasher)


def verify_proof(root, index, leaf, proof, size, hasher=None):
    """Check an inclusion proof against a known root.

    size is the number of leaves the tree had; the walk needs it to tell
    which levels promoted a lone node and therefore contributed no step.
    """
    hasher = hasher or DEFAULT_HASHER
    if index < 0 or index >= size:
        return False
    digest = hasher.leaf(leaf)
    position = index
    width = size
    used = 0
    while width > 1:
        if position % 2 == 0:
            if position + 1 < width:
                if used >= len(proof):
                    return False
                side, sibling = proof[used]
                used += 1
                if side != "right":
                    return False
                digest = hasher.node(digest, sibling)
        else:
            if used >= len(proof):
                return False
            side, sibling = proof[used]
            used += 1
            if side != "left":
                return False
            digest = hasher.node(sibling, digest)
        position //= 2
        width = width // 2
    return digest == root
