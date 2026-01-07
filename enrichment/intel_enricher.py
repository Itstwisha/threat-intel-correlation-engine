def enrich_iocs(iocs, threat_feed):
    """
    Enriches extracted IOCs using threat intelligence feeds.
    """
    enrichment_results = []

    for ioc_type, value in iocs.items():
        feed_key = f"malicious_{ioc_type}s"

        if feed_key in threat_feed and value in threat_feed[feed_key]:
            intel = threat_feed[feed_key][value]
            enrichment_results.append({
                "ioc_type": ioc_type,
                "ioc_value": value,
                "malicious": True,
                "confidence": intel["confidence"],
                "source": intel["source"],
                "mitre": intel["mitre"]
            })
        else:
            enrichment_results.append({
                "ioc_type": ioc_type,
                "ioc_value": value,
                "malicious": False
            })

    return enrichment_results
