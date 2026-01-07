import json
import os

from enrichment.ioc_extractor import extract_iocs
from enrichment.intel_enricher import enrich_iocs
from correlation.mitre_correlator import correlate_mitre
from correlation.risk_scorer import calculate_risk
from darkweb.darkweb_ingestor import ingest_darkweb_intel


def risk_priority(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    alerts = load_json("data/sample_alerts.json")
    threat_feed = load_json("data/threat_feeds.json")
    darkweb_feed = load_json("darkweb/darkweb_feed.json")

    final_results = []

    print("\n=== Threat Intelligence Correlation Engine ===\n")

    for alert in alerts:
        print(f"🛑 Processing Alert: {alert['alert_id']}")

        # 1️⃣ IOC Extraction
        iocs = extract_iocs(alert)

        # 2️⃣ Threat Intelligence Enrichment
        enrichment = enrich_iocs(iocs, threat_feed)

        # 3️⃣ MITRE ATT&CK Correlation
        mitre_summary = correlate_mitre(enrichment)

        # 4️⃣ Dark Web Intelligence Correlation
        darkweb_hits = ingest_darkweb_intel(darkweb_feed, enrichment)

        # 5️⃣ Alert Context (simulated SOC context)
        alert_context = {
            "username": alert.get("username", "admin"),
            "external_ip": True
        }

        # 6️⃣ Risk Scoring
        risk_score = calculate_risk(enrichment, alert_context)

        # Boost score if dark web intel exists
        if darkweb_hits:
            risk_score = min(risk_score + 10, 100)

        priority = risk_priority(risk_score)

        # Console Output
        print("🔍 Enriched IOCs:")
        for item in enrichment:
            print(item)

        print("\n🧠 MITRE Correlation Summary:")
        print(mitre_summary)

        if darkweb_hits:
            print("\n🔥 Dark Web Intelligence Matches:")
            for hit in darkweb_hits:
                print(hit)
        else:
            print("\nNo Dark Web intelligence matches.")

        print(f"\n📊 Final Risk Score: {risk_score}")
        print(f"🚨 Alert Priority: {priority}")
        print("\n" + "-" * 60 + "\n")

        # Save results for dashboard
        final_results.append({
            "alert_id": alert["alert_id"],
            "risk_score": risk_score,
            "priority": priority,
            "mitre_techniques": mitre_summary["techniques_observed"],
            "mitre_tactics": mitre_summary["tactics_observed"],
            "darkweb_hits": darkweb_hits,
            "enriched_iocs": enrichment
        })

    # Write output for SOC dashboard
    os.makedirs("output", exist_ok=True)

    with open("output/enriched_results.json", "w") as f:
        json.dump(final_results, f, indent=2)


    print("✅ Enriched results saved to output/enriched_results.json")


if __name__ == "__main__":
    main()
