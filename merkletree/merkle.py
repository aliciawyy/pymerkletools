import sys
import hashlib

try:
    import sha3
except ImportError:
    from warnings import warn
    warn("sha3 is not working!")

if sys.version_info.major == 2:
    import binascii


def byte_to_hex(x):
    if sys.version_info.major == 3:
        return x.hex()
    else:
        return binascii.hexlify(x)


hex_to_byte = bytearray.fromhex


def _get_hash_func(hash_type):
    supported_hash_types = {
        'sha256', 'md5', 'sha224', 'sha384', 'sha512',
        'sha3_256', 'sha3_224', 'sha3_384', 'sha3_512'
    }
    hash_type = hash_type.lower()
    if hash_type not in supported_hash_types:
        raise NotImplementedError(
            "`hash_type` {} is not supported. Supported types are "
            "{}".format(hash_type, supported_hash_types)
        )
    return getattr(hashlib, hash_type)


class MerkleTree(object):
    def __init__(self, hash_type="sha256"):
        self.hash_func = _get_hash_func(hash_type)
        self.levels = [[]]

    @property
    def leaves(self):
        return self.levels[-1]

    @property
    def num_leaves(self):
        return len(self.leaves)

    @property
    def is_tree_ready(self):
        return len(self.levels) > 1 or self.num_leaves == 1

    def add_leaves(self, values, do_hash=False):
        if not isinstance(values, (list, tuple)):
            values = [values]
        for v in values:
            if do_hash:
                v = v.encode('utf-8')
                v = self.hash_func(v).hexdigest()
            v = hex_to_byte(v)
            self.leaves.append(v)
        if self.is_tree_ready:
            self.levels = [self.leaves]

    def get_leaf(self, index):
        return byte_to_hex(self.leaves[index])

    def _make_tree(self):
        if self.is_tree_ready:
            return
        if self.num_leaves == 0:
            raise ValueError("No leaf to make tree!")
        while len(self.levels[0]) > 1:
            self._calculate_next_level()

    def _calculate_next_level(self):
        current_level = self.levels[0]
        num_leaves_current_level = len(current_level)
        new_level = [
            self.hash_func(current_level[i] + current_level[i+1]).digest()
            for i in range(0, num_leaves_current_level - 1, 2)
        ]
        if num_leaves_current_level % 2 == 1:
            new_level.append(current_level[-1])
        self.levels = [new_level] + self.levels

    @property
    def merkle_root(self):
        self._make_tree()
        return byte_to_hex(self.levels[0][0])

    def get_proof(self, index):
        self._make_tree()
        proof = []
        for i in range(len(self.levels) - 1, 0, -1):
            is_right_node = index % 2 == 1
            num_leaves_current_level = len(self.levels[i])
            if index == num_leaves_current_level - 1 and not is_right_node:
                index = int(index / 2.)
                continue
            sibling_index = index - 1 if is_right_node else index + 1
            sibling_pos = "left" if is_right_node else "right"
            sibling_value = byte_to_hex(self.levels[i][sibling_index])
            proof.append((sibling_pos, sibling_value))
            index = int(index / 2.)
        return proof

    def is_proof_valid(self, proof, target_hash):
        proof_hash_byte = hex_to_byte(target_hash)
        for sibling_pos, sibling_hash in proof:
            sibling_hash_byte = hex_to_byte(sibling_hash)
            if sibling_pos == "left":
                info = sibling_hash_byte + proof_hash_byte
            else:
                info = proof_hash_byte + sibling_hash_byte
            proof_hash_byte = self.hash_func(info).digest()
        return byte_to_hex(proof_hash_byte) == self.merkle_root
