from shadow_scout.net.ipindex import NetworkSet, ipv4_size, sample_ips


def test_overlap_and_contains():
    ns = NetworkSet()
    ns.add_many(["10.0.0.0/24", "10.0.1.0/25", "# comment", "garbage", "2001:db8::/32", "192.0.2.7"])
    assert ns.entries == 4
    assert ns.contains_ip("10.0.0.5")
    assert ns.contains_ip("192.0.2.7")
    assert not ns.contains_ip("10.0.2.1")
    blocked, total = ns.overlap_cidr("10.0.0.0/23")
    assert total == 512 and blocked == 256 + 128
    assert ns.overlap_cidr("10.0.0.0/8")[0] == 384 + 1 - 1  # 192.0.2.7 вне 10/8
    assert ns.overlapping_cidrs("10.0.0.0/23")[0].startswith("10.0.0.0/24")


def test_merge_adjacent():
    ns = NetworkSet()
    ns.add_many(["10.0.0.0/25", "10.0.0.128/25"])
    assert len(ns.v4) == 1
    assert ns.ipv4_count == 256


def test_sampling():
    ips = sample_ips("10.0.0.0/24", 4)
    assert len(ips) == 4 and all(ip.startswith("10.0.0.") for ip in ips)
    assert ipv4_size("10.0.0.0/22") == 1024
    assert sample_ips("10.0.0.1/32") == ["10.0.0.1"]
