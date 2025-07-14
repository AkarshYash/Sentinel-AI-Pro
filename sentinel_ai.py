import os
from openai import OpenAI
from dotenv import load_dotenv
import streamlit as st
import socket
import subprocess
import requests
import json
from ipwhois import IPWhois
import shodan
import whois
from langchain.tools import tool
import speech_recognition as sr
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
from attackcti import attack_client
from anthropic import Anthropic
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Initialize API clients
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
anthropic_client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

# ======================
# 🔐 CONFIGURATION
# ======================
class AIConfig:
    OPENAI_MODEL = "gpt-4-turbo-preview"
    ANTHROPIC_MODEL = "claude-3-opus-20240229"
    GEMINI_MODEL = "gemini-1.0-pro"
    LOCAL_LLM_ENDPOINT = "http://localhost:11434"

st.set_page_config(
    page_title="CyberSecurity Toolkit Pro",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Custom Styles
st.markdown("""
    <style>
    .big-title {
        font-size:48px !important;
        font-weight: 700;
        color: #00B4D8;
    }
    .subtle {
        font-size:16px !important;
        color: #888;
    }
    .tool-header {
        font-size:28px !important;
        color: #2E86AB;
        margin-bottom: 15px;
    }
    .dark-mode {
        background-color: #0E1117;
        color: white;
    }
    .light-mode {
        background-color: white;
        color: black;
    }
    </style>
""", unsafe_allow_html=True)

# ======================
# 🛠️ ENHANCED TOOL FUNCTIONS
# ======================

def resolve_target(target: str) -> str:
    """Resolve domain to IP if needed"""
    if not target.replace('.', '').isdigit():
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Could not resolve {target}")

def generate_pdf(title, user_input, ai_response, file_path="Sentinel_Report.pdf"):
    """Generate PDF report with user query and AI response"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, title)
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Generated on: {now}")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 100, "🧠 User Query:")
    c.setFont("Helvetica", 12)
    text_obj = c.beginText(50, height - 120)
    text_obj.textLines(user_input)
    c.drawText(text_obj)

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 220, "🤖 Sentinel AI Response:")
    c.setFont("Helvetica", 12)
    text_obj = c.beginText(50, height - 240)
    text_obj.textLines(ai_response)
    c.drawText(text_obj)

    c.save()
    return file_path

def get_ai_response(user_input, model_choice="openai"):
    """Multi-model AI response handler"""
    try:
        if model_choice == "openai":
            response = openai_client.chat.completions.create(
                model=AIConfig.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert"},
                    {"role": "user", "content": user_input}
                ]
            )
            return response.choices[0].message.content
            
        elif model_choice == "claude":
            response = anthropic_client.messages.create(
                model=AIConfig.ANTHROPIC_MODEL,
                max_tokens=1000,
                messages=[{"role": "user", "content": user_input}]
            )
            return response.content[0].text
            
        elif model_choice == "gemini":
            model = genai.GenerativeModel(AIConfig.GEMINI_MODEL)
            response = model.generate_content(user_input)
            return response.text
            
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return f"Error getting AI response: {str(e)}"

def virustotal_scan(file_hash_or_url):
    """VirusTotal API integration"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash_or_url}"
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
    response = requests.get(url, headers=headers)
    return response.json()

def shodan_lookup(ip):
    """Shodan device intelligence"""
    api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
    return api.host(ip)

def nuclei_scan(target):
    """Nuclei vulnerability scanner"""
    cmd = ["nuclei", "-u", target, "-json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)

def map_to_mitre(tactic):
    """MITRE ATT&CK mapper"""
    lift = attack_client()
    techniques = lift.get_techniques_by_tactic(tactic)
    return techniques

def evaluate_password_strength(password):
    """Password strength evaluator"""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_upper and has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    
    return {
        "score": score,
        "strength": ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(score, 4)],
        "feedback": [
            "Consider using a longer password with mixed characters",
            "Add more complexity with special characters and numbers",
            "Good start but could be stronger",
            "Strong password, consider making it longer",
            "Excellent password strength"
        ][min(score, 4)]
    }

# ======================
# 🛠️ TOOL IMPLEMENTATIONS
# ======================

def cve_lookup_tool():
    st.markdown('<div class="tool-header">🔍 CVE Lookup Tool</div>', unsafe_allow_html=True)
    cve_id = st.text_input("Enter CVE ID (e.g., CVE-2023-23397)", key="cve_input")

    if st.button("Search", key="cve_search"):
        if not cve_id:
            st.warning("Please enter a CVE ID")
            return

        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        try:
            with st.spinner("Fetching CVE details..."):
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if 'summary' in data:
                        col1, col2 = st.columns(2)
                        with col1:
                            st.subheader("Summary")
                            st.info(data.get('summary', 'N/A'))
                            st.subheader("CVSS Score")
                            st.code(data.get('cvss', 'N/A'))
                        with col2:
                            st.subheader("Published Date")
                            st.code(data.get('Published', 'N/A'))
                            st.subheader("References")
                            for ref in data.get('references', [])[:5]:
                                st.markdown(f"- [{ref[:50]}...]({ref})")

                        if st.button("📄 Export to PDF", key="cve_pdf"):
                            pdf_path = generate_pdf(
                                f"CVE Report - {cve_id}",
                                f"CVE ID: {cve_id}",
                                f"Summary: {data.get('summary', 'N/A')}\n\n"
                                f"CVSS: {data.get('cvss', 'N/A')}\n\n"
                                f"Published: {data.get('Published', 'N/A')}\n\n"
                                f"References: {', '.join(data.get('references', []))}"
                            )
                            with open(pdf_path, "rb") as f:
                                st.download_button(
                                    "⬇️ Download Report",
                                    f,
                                    file_name=f"{cve_id}_report.pdf",
                                    mime="application/pdf"
                                )
                    else:
                        st.warning("No details found for this CVE ID")
                else:
                    st.error("Failed to fetch CVE data")
        except Exception as e:
            st.error(f"Error: {str(e)}")

def ip_lookup_tool():
    st.markdown('<div class="tool-header">🌐 Domain to IP Resolver</div>', unsafe_allow_html=True)
    domain = st.text_input("Enter Domain or URL", placeholder="e.g., google.com", key="domain_input")

    if st.button("Resolve IP", key="ip_resolve"):
        if not domain:
            st.warning("Please enter a domain or URL")
            return

        try:
            with st.spinner("Resolving domain..."):
                ip = socket.gethostbyname(domain)
                st.success(f"✅ IP Address: `{ip}`")
                
                geo_url = f"https://ipapi.co/{ip}/json/"
                geo_res = requests.get(geo_url).json()
                st.subheader("Geolocation Info")
                st.json({
                    "City": geo_res.get("city"),
                    "Region": geo_res.get("region"),
                    "Country": geo_res.get("country_name"),
                    "ISP": geo_res.get("org")
                })
        except socket.gaierror:
            st.error("❌ Failed to resolve domain")
        except Exception as e:
            st.error(f"Error: {str(e)}")

def nmap_scanner():
    st.markdown('<div class="tool-header">🛰️ Nmap Scanner</div>', unsafe_allow_html=True)
    target = st.text_input("Enter target IP or domain", placeholder="e.g., scanme.nmap.org", key="nmap_target")
    scan_type = st.selectbox("Scan Type", ["Basic Scan", "OS Detection", "Port Range Scan", "Vulnerability Scan"], key="nmap_scan_type")

    if st.button("Start Scan", key="nmap_scan"):
        if not target:
            st.warning("Please enter a target")
            return

        try:
            with st.spinner(f"Running {scan_type}..."):
                if scan_type == "Basic Scan":
                    cmd = ["nmap", "-T4", target]
                elif scan_type == "OS Detection":
                    cmd = ["nmap", "-O", target]
                elif scan_type == "Port Range Scan":
                    cmd = ["nmap", "-p", "1-1000", target]
                elif scan_type == "Vulnerability Scan":
                    cmd = ["nmap", "--script", "vuln", target]

                result = subprocess.run(cmd, capture_output=True, text=True)
                
                st.subheader("Scan Results")
                st.code(result.stdout)
                
                if scan_type == "Vulnerability Scan" or st.checkbox("Show advanced details"):
                    nuclei_results = nuclei_scan(target)
                    st.subheader("Nuclei Vulnerability Results")
                    st.json(nuclei_results)
                
                if result.stderr:
                    st.warning("Scan warnings:")
                    st.code(result.stderr)
        except Exception as e:
            st.error(f"Error running Nmap: {str(e)}")

def threat_intel_tool():
    st.markdown('<div class="tool-header">🌐 Advanced Threat Intelligence</div>', unsafe_allow_html=True)
    ip = st.text_input("Enter IP Address", placeholder="e.g., 8.8.8.8", key="threat_ip")

    if st.button("Run Analysis", key="threat_analyze"):
        if not ip:
            st.warning("Please enter an IP address")
            return

        try:
            with st.spinner("Gathering threat intelligence..."):
                tab1, tab2, tab3 = st.tabs(["📍 Geolocation", "📄 WHOIS", "🛡️ Threat Data"])
                
                with tab1:
                    geo_url = f"https://ipapi.co/{ip}/json/"
                    geo_res = requests.get(geo_url).json()
                    st.json({
                        "IP": ip,
                        "City": geo_res.get("city"),
                        "Region": geo_res.get("region"),
                        "Country": geo_res.get("country_name"),
                        "ISP": geo_res.get("org")
                    })
                
                with tab2:
                    whois_url = f"https://rdap.arin.net/registry/ip/{ip}"
                    whois_res = requests.get(whois_url).json()
                    st.json(whois_res)
                
                with tab3:
                    try:
                        vt_result = virustotal_scan(ip)
                        st.subheader("VirusTotal Results")
                        st.json(vt_result)
                        
                        shodan_result = shodan_lookup(ip)
                        st.subheader("Shodan Results")
                        st.json(shodan_result)
                    except Exception as e:
                        st.error(f"API Error: {str(e)}")

        except Exception as e:
            st.error(f"Error fetching data: {str(e)}")

def password_audit_tool():
    st.markdown('<div class="tool-header">🔐 Password Strength Auditor</div>', unsafe_allow_html=True)
    password = st.text_input("Enter password to evaluate", type="password", key="password_input")
    
    if password:
        analysis = evaluate_password_strength(password)
        st.subheader("Password Analysis")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Strength Rating", analysis["strength"])
            st.progress(min((analysis["score"] + 1) / 5, 1.0))
        with col2:
            st.metric("Score", f"{analysis['score']}/5")
            st.info(analysis["feedback"])
        
        st.subheader("Recommendations")
        st.markdown("""
        - Use at least 12 characters
        - Combine uppercase, lowercase, numbers and symbols
        - Avoid common words and patterns
        - Consider using a password manager
        """)

def mitre_mapper_tool():
    st.markdown('<div class="tool-header">⚔️ MITRE ATT&CK Mapper</div>', unsafe_allow_html=True)
    tactic = st.selectbox("Select MITRE ATT&CK Tactic", [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact"
    ])
    
    if st.button("Map Techniques"):
        try:
            lift = attack_client()
            techniques = lift.get_techniques_by_tactic(tactic)
            st.subheader(f"Techniques for {tactic.replace('-', ' ').title()}")
            
            for tech in techniques:
                if 'technique_id' in tech:
                    with st.expander(f"{tech['technique_id']} - {tech['technique']}"):
                        st.markdown(f"**Description:** {tech.get('description', 'N/A')}")
                        st.markdown(f"**Platforms:** {', '.join(tech.get('platforms', []))}")
                        if 'mitigations' in tech:
                            st.markdown("**Mitigations:**")
                            for m in tech['mitigations']:
                                st.markdown(f"- {m.get('mitigation', 'N/A')}")
        except Exception as e:
            st.error(f"Error fetching MITRE data: {str(e)}")

def chat_with_ai():
    st.markdown('<div class="tool-header">💬 Multi-Model AI Assistant</div>', unsafe_allow_html=True)
    
    model_choice = st.selectbox(
        "Select AI Model",
        ["OpenAI GPT-4", "Anthropic Claude", "Google Gemini"],
        key="model_choice"
    )
    
    uploaded_files = st.file_uploader(
        "📎 Upload files for analysis", 
        accept_multiple_files=True,
        key="chat_upload"
    )
    
    use_voice = st.toggle("🎙️ Use Voice Typing", key="voice_toggle")
    text_input = ""
    
    if use_voice:
        if st.button("🎤 Start Recording", key="voice_record"):
            try:
                recognizer = sr.Recognizer()
                with sr.Microphone() as source:
                    st.info("🎙️ Listening... Speak now")
                    audio = recognizer.listen(source, timeout=5)
                    text_input = recognizer.recognize_google(audio)
                    st.success(f"🗣️ You said: {text_input}")
            except Exception as e:
                st.error(f"Voice recognition error: {str(e)}")
    else:
        text_input = st.text_area(
            "💻 Enter your query", 
            placeholder="Ask about threats, vulnerabilities, or security best practices...",
            key="chat_input",
            height=150
        )
    
    if st.button("🚀 Submit Query", key="chat_send"):
        if not text_input.strip():
            st.warning("Please enter a message")
            return
            
        try:
            with st.spinner("🔍 Analyzing..."):
                model_map = {
                    "OpenAI GPT-4": "openai",
                    "Anthropic Claude": "claude",
                    "Google Gemini": "gemini"
                }
                
                reply = get_ai_response(text_input, model_map[model_choice])
                
                st.markdown("### 🤖 AI Response")
                st.markdown(reply)
                
                if st.button("📄 Generate PDF Report"):
                    pdf_path = generate_pdf(
                        "AI Security Analysis Report",
                        text_input,
                        reply
                    )
                    with open(pdf_path, "rb") as pdf_file:
                        st.download_button(
                            "⬇️ Download Report",
                            pdf_file,
                            file_name="Security_Analysis_Report.pdf",
                            mime="application/pdf"
                        )
        except Exception as e:
            st.error(f"API Error: {str(e)}")

def main():
    dark_mode = st.sidebar.checkbox("🌙 Dark Mode", value=True)
    if dark_mode:
        st.markdown('<style>body {background-color: #0E1117; color: white;}</style>', 
                    unsafe_allow_html=True)
    
    st.markdown('<div class="big-title">🛡️ Sentinel AI Pro</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtle">Advanced Cybersecurity Toolkit with Multi-Model AI</div>', unsafe_allow_html=True)
    st.markdown("---")
    
    st.sidebar.header("🧰 Tools")
    tool = st.sidebar.radio(
        "Select Tool",
        [
            "🏠 Home",
            "📄 CVE Lookup",
            "🛰️ Nmap Scanner",
            "🌐 Threat Intel",
            "📍 IP Lookup",
            "⚔️ MITRE Mapper",
            "🔐 Password Audit",
            "💬 AI Assistant"
        ]
    )
    
    if tool == "🏠 Home":
        st.success("## 🚀 Welcome to Sentinel AI Pro")
        st.markdown("""
        **Enhanced Features:**
        - **Multi-Model AI** (GPT-4, Claude 3, Gemini)
        - **VirusTotal Integration** for file/URL scanning
        - **Shodan Lookup** for device intelligence
        - **Nuclei Vulnerability Scanner**
        - **MITRE ATT&CK Framework Mapper**
        - **Password Strength Auditor**
        - **Dark/Light Mode** toggle
        """)
        
        st.markdown("### Quick Start Guide")
        st.markdown("""
        1. Use the sidebar to select a tool
        2. For threat analysis, try the **Threat Intel** tool
        3. For vulnerability scanning, use **Nmap Scanner**
        4. Get AI-powered advice with **AI Assistant**
        """)
    elif tool == "📄 CVE Lookup":
        cve_lookup_tool()
    elif tool == "🛰️ Nmap Scanner":
        nmap_scanner()
    elif tool == "🌐 Threat Intel":
        threat_intel_tool()
    elif tool == "📍 IP Lookup":
        ip_lookup_tool()
    elif tool == "⚔️ MITRE Mapper":
        mitre_mapper_tool()
    elif tool == "🔐 Password Audit":
        password_audit_tool()
    elif tool == "💬 AI Assistant":
        chat_with_ai()
    
    st.markdown("---")
    col1, col2, col3 = st.columns([2,1,1])
    
    with col1:
        st.markdown("Made with ❤️ by Akarsh Chaturvedi • `Sentinel AI Pro v2.0`")
    
    with col2:
        if st.button("👨‍💻 About the Developer"):
            st.sidebar.markdown("""
            **Akarsh Chaturvedi**  
            [LinkedIn](https://www.linkedin.com/in/akarsh-chaturvedi-259271236?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base_contact_details%3BF1ac4BMXRzCmKl89pCoMIw%3D%3D)  
            [GitHub](https://github.com/AkarshYash)
            """)
    
    with col3:
        st.markdown("""
        <div style="display: flex; gap: 10px;">
            <a href="https://www.linkedin.com/in/akarsh-chaturvedi-259271236?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base_contact_details%3B%2FiLGZsvrQs%2BBNzYBV%2BTO4Q%3D%3D" target="_blank">
                <img src="https://content.linkedin.com/content/dam/me/business/en-us/amp/brand-site/v2/bg/LI-Bug.svg.original.svg" width="24">
            </a>
            <a href="https://github.com/AkarshYash" target="_blank">
                <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" width="24">
            </a>
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()