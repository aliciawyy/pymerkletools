import pymerkletree as pm

# Construct a Merkle Tree
mt = pm.MerkleTree(hash_type="sha256")  # default is sha256
# valid hashTypes include all crypto hash algorithms
# such as 'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512'
# as well as the SHA3 family of algorithms
# including 'SHA3-224', 'SHA3-256', 'SHA3-384', and 'SHA3-512'

mt.add_leaves(["a", "b", "word", "c"], do_hash=True)

print("Merkle Root = ", mt.merkle_root)

proof = mt.get_proof(2)

print("Proof of the second leaf\n", proof)

print("Is proof valid for the second leaf (expected True): ",
      mt.is_proof_valid(proof, mt.get_leaf(2)))

print("Is proof valid for the third leaf (expected False): ",
      mt.is_proof_valid(proof, mt.get_leaf(3)))
