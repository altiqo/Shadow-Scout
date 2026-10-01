from shadow_scout.analysis.discovery import DiscoveryEngine, DiscoveryOptions


async def test_discovery_finds_small_clean_isp(services):
    engine = DiscoveryEngine(services)
    logs: list[str] = []
    options = DiscoveryOptions(country="SE", max_candidates=10, keyword_filter=False, min_ipv4=1)
    results = await engine.discover(options, log=logs.append)
    asns = [c.asn for c in results]
    assert 99999 in asns and 42708 in asns
    best = results[0]
    assert best.asn == 99999
    assert best.pdb_type == "isp"
    provider = best.to_provider()
    assert provider.asns == [99999] and provider.source == "discovered"


def test_keyword_filter():
    assert DiscoveryEngine.keyword_pass("Tiny Hosting AB", ["host"], ["university"])
    assert not DiscoveryEngine.keyword_pass("University Hosting", ["host"], ["university"])
