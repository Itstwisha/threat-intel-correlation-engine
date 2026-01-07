MITRE_SEVERITY = {
    "T1078": 30,  # Valid Accounts
    "T1110": 30,  # Brute Force
    "T1566": 20,  # Phishing
    "T1204": 20,  # User Execution
    "T1046": 10   # Network Discovery
}

CONFIDENCE_SCORE = {
    "High": 40,
    "Medium": 25,
    "Low": 10
}

IOC_IMPACT = {
    "file_hash": 30,
    "domain": 20,
    "ip": 15
}

def calculate_risk(enriched_iocs, alert_context):
    """
    Calculates total risk score for an alert.
    """
    risk_score = 0

    for ioc in enriched_iocs:
        if not ioc.get("malicious"):
            continue

        # Confidence
        risk_score += CONFIDENCE_SCORE.get(ioc.get("confidence"), 0)

        # IOC impact
        risk_score += IOC_IMPACT.get(ioc.get("ioc_type"), 0)

        # MITRE impact
        for technique in ioc.get("mitre", []):
            risk_score += MITRE_SEVERITY.get(technique, 0)

    # Context-based scoring
    if alert_context.get("username") == "admin":
        risk_score += 10

    if alert_context.get("external_ip"):
        risk_score += 10

    return min(risk_score, 100)

