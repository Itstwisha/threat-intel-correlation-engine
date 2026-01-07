def ingest_darkweb_intel(darkweb_feed, enriched_iocs):
    """
    Correlates dark web intelligence with enriched IOCs.
    """
    darkweb_hits = []

    for intel in darkweb_feed:
        for ioc in enriched_iocs:
            if (
                intel["ioc_type"] == ioc["ioc_type"]
                and intel["ioc_value"] == ioc["ioc_value"]
            ):
                darkweb_hits.append({
                    "ioc_type": intel["ioc_type"],
                    "ioc_value": intel["ioc_value"],
                    "darkweb_context": intel["context"],
                    "confidence": intel["confidence"],
                    "mitre": intel["mitre"],
                    "source": "Dark Web Monitoring"
                })

    return darkweb_hits

