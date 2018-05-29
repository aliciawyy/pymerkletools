import sys
import hashlib

try:
    import sha3
except ImportError:
    from warnings import warn
    warn("sha3 is not working!")

if sys.version_info.major == 2:
    import binascii


def to_hex(x):
    if sys.version_info.major == 3:
        return x.hex()
    else:
        return binascii.hexlify(x)


class MerkleTools(object):
    def __init__(self, hash_type="sha256"):
        hash_type = hash_type.lower()
        if hash_type in self.supported_hash_types:
            self.hash_func = getattr(hashlib, hash_type)
        else:
            raise NotImplementedError(
                "`hash_type` {} is not supported. Supported types are "
                "{}".format(hash_type, self.supported_hash_types)
            )
        self.leaves = []
        self.levels = None

    @property
    def supported_hash_types(self):
        return {
            'sha256', 'md5', 'sha224', 'sha384', 'sha512',
            'sha3_256', 'sha3_224', 'sha3_384', 'sha3_512'
        }

    def add_leaf(self, values, do_hash=False):
        if not isinstance(values, (list, tuple)):
            values = [values]
        for v in values:
            if do_hash:
                v = v.encode('utf-8')
                v = self.hash_func(v).hexdigest()
            v = bytearray.fromhex(v)
            self.leaves.append(v)

    def get_leaf(self, index):
        return to_hex(self.leaves[index])

    @property
    def num_leaves(self):
        return len(self.leaves)

    def _calculate_next_level(self):
        solo_leave = None
        current_level = self.levels[0]
        num_leaves = len(current_level)
        if num_leaves % 2 == 1:
            solo_leave = current_level[-1]
            num_leaves -= 1

        new_level = []
        for i in range(0, num_leaves, 2):
            value = current_level[i] + current_level[i+1]
            new_level.append(self.hash_func(value).digest())
        if solo_leave is not None:
            new_level.append(solo_leave)
        self.levels = [new_level] + self.levels

    def make_tree(self):
        if self.num_leaves == 0:
            raise ValueError("No leaves to make tree!")
        self.levels = [self.leaves]
        while len(self.levels[0]) > 1:
            self._calculate_next_level()
        self.is_tree_ready = True

    def get_merkle_root(self):
        if self.levels is not None:
            return to_hex(self.levels[0][0])

    def get_proof(self, index):
        if self.levels is None or index > len(self.leaves)-1 or index < 0:
            return None
        proof = []
        for x in range(len(self.levels) - 1, 0, -1):
            level_len = len(self.levels[x])
            if (index == level_len - 1) and (level_len % 2 == 1):  # skip if this is an odd end node
                index = int(index / 2.)
                continue
            is_right_node = index % 2
            sibling_index = index - 1 if is_right_node else index + 1
            sibling_pos = "left" if is_right_node else "right"
            sibling_value = to_hex(self.levels[x][sibling_index])
            proof.append({sibling_pos: sibling_value})
            index = int(index / 2.)
        return proof

    def validate_proof(self, proof, target_hash, merkle_root):
        merkle_root = bytearray.fromhex(merkle_root)
        target_hash = bytearray.fromhex(target_hash)
        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                try:
                    # the sibling is a left node
                    sibling = bytearray.fromhex(p['left'])
                    proof_hash = self.hash_func(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = bytearray.fromhex(p['right'])
                    proof_hash = self.hash_func(proof_hash + sibling).digest()
            return proof_hash == merkle_root
