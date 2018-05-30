import hashlib
from pytest import raises
from merkletree import MerkleTree, byte_to_hex, hex_to_byte


def test_init_raises():
    raises(NotImplementedError, MerkleTree, "sha_dummy")


def test_byte_hex():
    mt = MerkleTree()
    v_hex = mt.hash_func(str.encode("000")).hexdigest()
    v_byte = hex_to_byte(v_hex)
    assert v_hex == byte_to_hex(v_byte)


def test_add_leaf():
    mt = MerkleTree()
    mt.add_leaves("tierion", do_hash=True)
    mt.add_leaves(["bitcoin", "blockchain"], do_hash=True)
    assert mt.num_leaves == 3
    expected_root = ('765f15d171871b00034ee55e48ffdf76afbc44ed0bcff5'
                     'c82f31351d333c2ed1')
    assert expected_root == mt.merkle_root


def test_merkle_root_raises():
    mt = MerkleTree()
    with raises(ValueError):
        _ = mt.merkle_root


def test_get_proof():
    mt = MerkleTree()
    mt.add_leaves("tierion", do_hash=True)
    mt.add_leaves(["bitcoin", "blockchain"], do_hash=True)
    proof_1 = mt.get_proof(1)
    for p in proof_1:
        try:
            assert p['left'] == '2da7240f6c88536be72abe9f04e454c6478ee29709fc3729ddfb942f804fbf08'
        except:
            assert p['right'] == 'ef7797e13d3a75526946a3bcf00daec9fc9c9c4d51ddc7cc5df888f74dd434d1'


def test_merkle_root_basics():
    v_left, v_right = (
        'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb',
        'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'
    )
    expected_root = hashlib.sha256(
        hex_to_byte(v_left) + hex_to_byte(v_right)
    ).hexdigest()

    mt = MerkleTree()
    mt.add_leaves([v_left, v_right])
    assert expected_root == mt.merkle_root
    mt.add_leaves(v_right)
    assert expected_root != mt.merkle_root


def test_merkle_root_one_leaf():
    mt = MerkleTree()
    v_hex = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
    mt.add_leaves(v_hex)
    assert mt.is_tree_ready
    assert v_hex == mt.get_leaf(0)
    assert v_hex == mt.merkle_root


def test_merkle_root():
    expected_root = ("d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420"
                     "bf11f1eced610dba")
    mt = MerkleTree()
    mt.add_leaves('a', True)
    mt.add_leaves('b', True)
    mt.add_leaves('c', True)
    mt.add_leaves('d', True)
    mt.add_leaves('e', True)
    assert expected_root == mt.merkle_root

    mt = MerkleTree()
    mt.add_leaves(['a', 'b', 'c', 'd', 'e'], True)
    assert expected_root == mt.merkle_root

    mt = MerkleTree()
    mt.add_leaves([
        'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
        '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
        '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
        '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
        '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea'
    ])
    assert expected_root == mt.merkle_root


def test_md5_tree():
    bLeftmd5 = '0cc175b9c0f1b6a831c399e269772661'
    bRightmd5 = '92eb5ffee6ae2fec3ad71c777531578f'
    expected_root = hashlib.md5(
        bytearray.fromhex(bLeftmd5) + bytearray.fromhex(bRightmd5)
    ).hexdigest()

    mt = MerkleTree('md5')
    mt.add_leaves([bLeftmd5, bRightmd5])
    assert mt.merkle_root == expected_root


def test_proof_nodes():
    v_left, v_right = (
        'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb',
        'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'
    )
    mt = MerkleTree()
    mt.add_leaves([v_left, v_right])
    assert [{"right": v_right}] == mt.get_proof(0)
    assert [{"left": v_left}] == mt.get_proof(1)


def test_bad_proof():
    bLeft = 'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb'
    bRight = 'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'

    mt = MerkleTree()
    mt.add_leaves(bLeft)
    mt.add_leaves(bRight)
    proof = mt.get_proof(1)
    is_valid = mt.validate_proof(proof, bRight, bLeft)
    assert not is_valid


def test_validate_5_leaves():
    mt = MerkleTree()
    mt.add_leaves([
        'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
        '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
        '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
        '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
        '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea'
    ])

    # bad proof
    proof = mt.get_proof(3)
    is_valid = mt.validate_proof(proof, 'badc3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4', 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba')
    assert not is_valid

    # good proof
    proof = mt.get_proof(4)
    is_valid = mt.validate_proof(proof, '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea', 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba')
    assert is_valid

    proof = mt.get_proof(1)
    is_valid = mt.validate_proof(proof, '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d', 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba')
    assert is_valid


# testing other hash functions
def test_sha224():
    mt = MerkleTree(hash_type='sha224')
    mt.add_leaves([
        '90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809',
        '35f757ad7f998eb6dd3dd1cd3b5c6de97348b84a951f13de25355177'
    ])
    assert mt.merkle_root == 'f48bc49bb77d3a3b1c8f8a70db693f41d879189cd1919f8326067ad7'
    assert mt.get_proof(0)[0]['right'] == '35f757ad7f998eb6dd3dd1cd3b5c6de97348b84a951f13de25355177'
    is_valid = mt.validate_proof(mt.get_proof(0), '90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809', 'f48bc49bb77d3a3b1c8f8a70db693f41d879189cd1919f8326067ad7')
    assert is_valid


def test_sha256():
    mt = MerkleTree(hash_type='sha256')
    mt.add_leaves([
        '1516f000de6cff5c8c63eef081ebcec2ad2fdcf7034db16045d024a90341e07d',
        'e20af19f85f265579ead2578859bf089c92b76a048606983ad83f27ba8f32f1a'
    ])
    assert mt.merkle_root == '77c654b3d1605f78ed091cbd420c939c3feff7d57dc30c171fa45a5a3c81fd7d'
    assert mt.get_proof(0)[0]['right'] == 'e20af19f85f265579ead2578859bf089c92b76a048606983ad83f27ba8f32f1a'
    is_valid = mt.validate_proof(mt.get_proof(0), '1516f000de6cff5c8c63eef081ebcec2ad2fdcf7034db16045d024a90341e07d', '77c654b3d1605f78ed091cbd420c939c3feff7d57dc30c171fa45a5a3c81fd7d')
    assert is_valid


def test_sha384():
    mt = MerkleTree(hash_type='sha384')
    mt.add_leaves([
        '84ae8c6367d64899aef44a951edfa4833378b9e213f916c5eb8492cc37cb951c726e334dace7dbe4bb1dc80c1efe33d0',
        '368c89a00446010def75ad7b179cea9a3d24f8cbb7e2755a28638d194809e7b614eb45453665032860b6c1a135fb6e8b'
    ])
    assert mt.merkle_root == 'c363aa3b824e3f3b927034fab826eff61a9bfa2030ae9fc4598992edf9f3e42f8b497d6742946caf7a771429eb1745cf'
    assert mt.get_proof(0)[0]['right'] == '368c89a00446010def75ad7b179cea9a3d24f8cbb7e2755a28638d194809e7b614eb45453665032860b6c1a135fb6e8b'
    is_valid = mt.validate_proof(mt.get_proof(0), '84ae8c6367d64899aef44a951edfa4833378b9e213f916c5eb8492cc37cb951c726e334dace7dbe4bb1dc80c1efe33d0', 'c363aa3b824e3f3b927034fab826eff61a9bfa2030ae9fc4598992edf9f3e42f8b497d6742946caf7a771429eb1745cf')
    assert is_valid


def test_sha512():
    mt = MerkleTree(hash_type='sha512')
    mt.add_leaves([
        'c0a8907588c1da716ce31cbef05da1a65986ec23afb75cd42327634dd53d754be6c00a22d6862a42be5f51187a8dff695c530a797f7704e4eb4b473a14ab416e',
        'df1e07eccb2a2d4e1b30d11e646ba13ddc426c1aefbefcff3639405762f216fdcc40a684f3d1855e6d465f99fd9547e53fa8a485f18649fedec5448b45963976'
    ])
    assert mt.merkle_root == 'd9d27704a3a785d204257bfa2b217a1890e55453b6686f091fa1be8aa2b265bc06c285a909459996e093546677c3f392458d7b1fc34a994a86689ed4100e8337'
    assert mt.get_proof(0)[0]['right'] == 'df1e07eccb2a2d4e1b30d11e646ba13ddc426c1aefbefcff3639405762f216fdcc40a684f3d1855e6d465f99fd9547e53fa8a485f18649fedec5448b45963976'
    is_valid = mt.validate_proof(mt.get_proof(0), 'c0a8907588c1da716ce31cbef05da1a65986ec23afb75cd42327634dd53d754be6c00a22d6862a42be5f51187a8dff695c530a797f7704e4eb4b473a14ab416e', 'd9d27704a3a785d204257bfa2b217a1890e55453b6686f091fa1be8aa2b265bc06c285a909459996e093546677c3f392458d7b1fc34a994a86689ed4100e8337')
    assert is_valid


def test_sha3_224():
    mt = MerkleTree(hash_type='sha3_224')
    mt.add_leaves([
        '6ed712b9472b671fd70bb950dc4ccfce197c92a7969f6bc2aa6b6d9f',
        '08db5633d406804d044a3e67683e179b5ee51249ed2139c239d1e65a'
    ])
    assert mt.merkle_root == '674bc9f53d5c666174cdd3ccb9df04768dfb7759655e7d937aef0c3a'
    assert mt.get_proof(0)[0]['right'] == '08db5633d406804d044a3e67683e179b5ee51249ed2139c239d1e65a'
    is_valid = mt.validate_proof(mt.get_proof(0), '6ed712b9472b671fd70bb950dc4ccfce197c92a7969f6bc2aa6b6d9f', '674bc9f53d5c666174cdd3ccb9df04768dfb7759655e7d937aef0c3a')
    assert is_valid


def test_sha3_256():
    mt = MerkleTree(hash_type='sha3_256')
    mt.add_leaves([
        '1d7d4ea1cc029ca460e486642830c284657ea0921235c46298b51f0ed1bb7bf7',
        '89b9e14eae37e999b096a6f604adefe7feea4dc240ccecb5e4e92785cffc7070'
    ])
    assert mt.merkle_root == '6edf674f5ce762e096c3081aee2a0a977732e07f4d704baf34f5e3804db03343'
    assert mt.get_proof(0)[0]['right'] == '89b9e14eae37e999b096a6f604adefe7feea4dc240ccecb5e4e92785cffc7070'
    is_valid = mt.validate_proof(mt.get_proof(0), '1d7d4ea1cc029ca460e486642830c284657ea0921235c46298b51f0ed1bb7bf7', '6edf674f5ce762e096c3081aee2a0a977732e07f4d704baf34f5e3804db03343')
    assert is_valid


def test_sha3_384():
    mt = MerkleTree(hash_type='sha3_384')
    mt.add_leaves([
        'e222605f939aa69b964a0a03d7075676bb3dbb40c3bd10b22f0adcb149434e7c1085c206f0e3371470a49817aa6d5b16',
        'ae331b6f8643ed7e404471c81be9a74f73fc84ffd5140a0ec9aa8596fa0d0a2ded5f7b780bb2fbfc4e2226ee2a04a2fa'
    ])
    assert mt.merkle_root == 'bd54df0015fa0d4fee713fbf5c8ae232c93239c75fb9d41c7dd7a9278711764a6ee83c81766b3945ed94030254537b57'
    assert mt.get_proof(0)[0]['right'] == 'ae331b6f8643ed7e404471c81be9a74f73fc84ffd5140a0ec9aa8596fa0d0a2ded5f7b780bb2fbfc4e2226ee2a04a2fa'
    is_valid = mt.validate_proof(mt.get_proof(0), 'e222605f939aa69b964a0a03d7075676bb3dbb40c3bd10b22f0adcb149434e7c1085c206f0e3371470a49817aa6d5b16', 'bd54df0015fa0d4fee713fbf5c8ae232c93239c75fb9d41c7dd7a9278711764a6ee83c81766b3945ed94030254537b57')
    assert is_valid


def test_sha3_512():
    mt = MerkleTree(hash_type='sha3_512')
    mt.add_leaves([
        '004a237ea808cd9375ee9db9f85625948a890c54e2c30f736f54c969074eb56f0ff3d43dafb4b40d5d974acc1c2a68c046fa4d7c2c20cab6df956514040d0b8b',
        '0b43a85d08c05252d0e23c96bc6b1bda11dfa787049ff452b3c86f4c6135e870c058c05131f199ef8619cfac937a736bbc936a667e4d96a5bf68e4056ce5fdce'
    ])
    assert mt.merkle_root == '3dff3f19b67628591d294cba2c07ed20d20d83e1624af8c1dca8fcf096127b9f86435e2d6a84ca4cee526525cacd1c628bf06ee938983413afafbb4598c5862a'
    assert mt.get_proof(0)[0]['right'] == '0b43a85d08c05252d0e23c96bc6b1bda11dfa787049ff452b3c86f4c6135e870c058c05131f199ef8619cfac937a736bbc936a667e4d96a5bf68e4056ce5fdce'
    is_valid = mt.validate_proof(mt.get_proof(0), '004a237ea808cd9375ee9db9f85625948a890c54e2c30f736f54c969074eb56f0ff3d43dafb4b40d5d974acc1c2a68c046fa4d7c2c20cab6df956514040d0b8b', '3dff3f19b67628591d294cba2c07ed20d20d83e1624af8c1dca8fcf096127b9f86435e2d6a84ca4cee526525cacd1c628bf06ee938983413afafbb4598c5862a')
    assert is_valid