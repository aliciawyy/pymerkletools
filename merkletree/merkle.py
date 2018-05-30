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
        return self.num_leaves == 1 or len(self.levels) > 1

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
        self.levels = [self.leaves]
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
            level_len = len(self.levels[i])
            if index == level_len - 1 and level_len % 2 == 1:
                index = int(index / 2.)
                continue
            is_right_node = index % 2 == 1
            sibling_index = index - 1 if is_right_node else index + 1
            sibling_pos = "left" if is_right_node else "right"
            sibling_value = byte_to_hex(self.levels[i][sibling_index])
            proof.append({sibling_pos: sibling_value})
            index = int(index / 2.)
        return proof

    def validate_proof(self, proof, target_hash, merkle_root):
        merkle_root = hex_to_byte(merkle_root)
        target_hash = hex_to_byte(target_hash)
        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                try:
                    # the sibling is a left node
                    sibling = hex_to_byte(p['left'])
                    proof_hash = self.hash_func(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = hex_to_byte(p['right'])
                    proof_hash = self.hash_func(proof_hash + sibling).digest()
            return proof_hash == merkle_root
