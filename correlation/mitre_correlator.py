MITRE_TACTICS = {
    "T1566": "Initial Access",
    "T1078": "Credential Access",
    "T1110": "Credential Access",
    "T1204": "Execution",
    "T1046": "Discovery"
}

def correlate_mitre(enriched_iocs):
    """
    Correlates MITRE ATT&CK techniques into attack patterns.
    """
    tactics_seen = {}
    techniques = set()

    for ioc in enriched_iocs:
        if not ioc.get("malicious"):
            continue

        for tech in ioc.get("mitre", []):
            techniques.add(tech)
            tactic = MITRE_TACTICS.get(tech, "Unknown")
            tactics_seen.setdefault(tactic, []).append(tech)

    attack_chain = list(tactics_seen.keys())

    correlated = {
        "techniques_observed": list(techniques),
        "tactics_observed": tactics_seen,
        "attack_chain_length": len(attack_chain),
        "multi_stage_attack": len(attack_chain) >= 2
    }

    return correlated

