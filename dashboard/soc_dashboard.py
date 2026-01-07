import json
import streamlit as st
import pandas as pd

st.set_page_config(page_title="SOC Threat Intel Dashboard", layout="wide")

st.title("🛡️ SOC Threat Intelligence Dashboard")

with open("output/enriched_results.json") as f:
    data = json.load(f)

# Sidebar filter
alert_ids = [item["alert_id"] for item in data]
selected_alert = st.sidebar.selectbox("Select Alert", alert_ids)

alert = next(item for item in data if item["alert_id"] == selected_alert)

# Top metrics
col1, col2, col3 = st.columns(3)
col1.metric("Risk Score", alert["risk_score"])
col2.metric("Priority", alert["priority"])
col3.metric("MITRE Techniques", len(alert["mitre_techniques"]))

st.divider()

# MITRE Section
st.subheader("🧠 MITRE ATT&CK Techniques Observed")
if alert["mitre_techniques"]:
    st.write(", ".join(alert["mitre_techniques"]))
else:
    st.write("No MITRE techniques identified.")

# Dark Web Section
st.subheader("🔥 Dark Web Intelligence")
if alert["darkweb_hits"]:
    for hit in alert["darkweb_hits"]:
        st.warning(f"""
        **IOC:** {hit['ioc_value']}  
        **Context:** {hit['darkweb_context']}  
        **Confidence:** {hit['confidence']}
        """)
else:
    st.success("No Dark Web intelligence found.")

# Enriched IOCs Table
st.subheader("🔍 Enriched Indicators of Compromise")
ioc_df = pd.DataFrame(alert["enriched_iocs"])
st.dataframe(ioc_df, use_container_width=True)

