import streamlit as st
import subprocess
import os

st.title("🛡️ DNS Firewall – Client")
st.write("Enter a domain to check if it's **allowed** or **blocked**.")

domain = st.text_input("🔍 Domain Name")

if st.button("Check Domain"):
    if domain.strip():
        try:
            result = subprocess.run(
                ["python3", "client.py", domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                text=True,
                cwd="client"  # Set working directory to where client.py exists
            )
            output = result.stdout.strip()
            if "allowed" in output.lower():
                st.success(f"✅ {domain} is ALLOWED")
            elif "blocked" in output.lower():
                st.error(f"⛔ {domain} is BLOCKED")
            elif "timeout" in output.lower():
                st.warning("⚠️ Request timed out.")
            elif output.startswith("ERROR"):
                st.warning(f"⚠️ Client error: {output}")
            else:
                st.info(f"ℹ️ Server response: {output}")
        except subprocess.TimeoutExpired:
            st.error("🚫 DNS query timed out.")
        except Exception as e:
            st.error(f"🔧 Failed to run client: {e}")
    else:
        st.warning("Please enter a valid domain.")

