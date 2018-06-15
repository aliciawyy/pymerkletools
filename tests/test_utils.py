from pymerkletree import utils


def test_compute_hash():
    data = ["2016-05-28", {"SHY": ".5", "SPY": ".5"}]
    expected = ("cf494b434cb87365614c01c27506ea800119e556151965129fc3b"
                "98b11d4f10c")
    assert expected == utils.compute_hash(data)


def test_byte_hex():
    v_hex = utils.compute_hash("0000")
    v_byte = utils.hex_to_byte(v_hex)
    assert v_hex == utils.byte_to_hex(v_byte)
