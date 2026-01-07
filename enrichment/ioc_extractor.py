def extract_iocs(alert):
    """
    Extracts Indicators of Compromise from a security alert.
    """
    iocs = {}

    if alert.get("ip"):
        iocs["ip"] = alert["ip"]

    if alert.get("domain"):
        iocs["domain"] = alert["domain"]

    if alert.get("file_hash"):
        iocs["file_hash"] = alert["file_hash"]

    return iocs

