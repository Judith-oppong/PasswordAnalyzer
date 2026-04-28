import streamlit as st
import random
import string
import pandas as pd
import matplotlib.pyplot as plt
from analyzer import analyze_password, log_result
import time
import base64

from cryptography.fernet import Fernet

# Initialize encryption key
if "vault_key" not in st.session_state:
    st.session_state.vault_key = Fernet.generate_key()

def get_cipher():
    return Fernet(st.session_state.vault_key)

def encrypt_password(password):
    return get_cipher().encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return get_cipher().decrypt(encrypted_password.encode()).decode()


def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


def generate_passphrase(word_count=4):
    words = [
        "sunset", "river", "forest", "ocean", "tiger", "coffee", "lemon",
        "storm", "breeze", "mountain", "cloud", "ember", "falcon", "lotus",
        "maple", "canyon", "aurora", "harbor", "glacier", "willow"
    ]
    phrase = ''.join(random.choice(words).capitalize() for _ in range(word_count))
    phrase += str(random.randint(10, 99))
    phrase += random.choice("!@#$%^&*")
    return phrase


def format_rule(ok, label):
    color = "#4CAF50" if ok else "#F44336"
    icon = "✅" if ok else "❌"
    return f'<span style="color: {color}; font-weight: bold;">{icon} {label}</span>'


def copy_to_clipboard(text, key):
    escaped = text.replace("\\", "\\\\").replace("'", "\\'")
    st.markdown(
        f"<button onclick=\"navigator.clipboard.writeText('{escaped}')\">Copy</button>",
        unsafe_allow_html=True,
    )


def get_image_background(path):
    ext = path.split(".")[-1].lower()
    mime = "gif" if ext == "gif" else "jpeg" if ext in ("jpg", "jpeg") else "png"
    with open(path, "rb") as f:
        data = f.read()
    encoded = base64.b64encode(data).decode("utf-8")
    return f"data:image/{mime};base64,{encoded}"


st.set_page_config(page_title="Password Analyzer", page_icon="🔐", layout="wide")

if "password_vault" not in st.session_state:
    st.session_state.password_vault = []
if "generated_password" not in st.session_state:
    st.session_state.generated_password = ""
if "generated_passphrase" not in st.session_state:
    st.session_state.generated_passphrase = ""
if "analysis" not in st.session_state:
    st.session_state.analysis = None
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = False

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Controls")
    dark_mode = st.checkbox("Dark Mode", value=st.session_state.dark_mode, key="dark_toggle")
    st.session_state.dark_mode = dark_mode
    animate_bg = st.checkbox("Background Image", value=True)
    show_password = st.checkbox("Show password", value=False)
    generate_length = st.slider("Generated password length", 12, 24, 16)
    passphrase_word_count = st.slider("Passphrase word count", 3, 6, 4)
    show_stats = st.checkbox("Show statistics panel", value=True)

    st.markdown("---")
    st.markdown("### Privacy")
    st.info("We store only strength and entropy. Raw passwords are never saved.")
    st.markdown("---")
    st.markdown("### Tips")
    st.write("- Use a passphrase for better memorability.")
    st.write("- Avoid reused or leaked passwords.")
    st.write("- Longer passwords are stronger than short variations.")

    st.markdown("---")
    st.markdown("### Password Manager")
    st.write("Store generated passwords locally in this session.")
    if st.button("Save Current Generated Password"):
        if st.session_state.generated_password:
            st.session_state.password_vault.append({
                "type": "password",
                "value": encrypt_password(st.session_state.generated_password),
                "timestamp": time.time()
            })
            st.success("Password saved to vault.")
        else:
            st.warning("No password to save.")
    if st.button("Save Current Passphrase"):
        if st.session_state.generated_passphrase:
            st.session_state.password_vault.append({
                "type": "passphrase",
                "value": encrypt_password(st.session_state.generated_passphrase),
                "timestamp": time.time()
            })
            st.success("Passphrase saved to vault.")
        else:
            st.warning("No passphrase to save.")
    if st.session_state.password_vault:
        st.write("Stored items:")
        for i, item in enumerate(st.session_state.password_vault):
            decrypted = decrypt_password(item["value"])
            st.write(f"{i+1}. {item['type'].capitalize()}: {'*' * len(decrypted)}")
            colA, colB = st.columns(2)
            with colA:
                if st.button(f"Reveal {i+1}", key=f"reveal_{i}"):
                    st.info(decrypted)
            with colB:
                if st.button(f"Delete {i+1}", key=f"delete_{i}"):
                    st.session_state.password_vault.pop(i)
                    st.rerun()
    else:
        st.info("No items saved yet.")

    st.markdown("---")
    st.markdown("### Password Manager Recommendation")
    st.write("For secure storage and generation, consider these free tools:")
    st.markdown("- [Bitwarden](https://bitwarden.com) - Open-source, cross-platform")
    st.markdown("- [KeePassXC](https://keepassxc.org) - Local, no cloud required")
    st.markdown("- [LastPass](https://lastpass.com) - Cloud-based with autofill")
    st.caption("Use a manager to avoid reusing passwords and store strong ones safely.")

# ── Background & Theme ───────────────────────────────────────────────────────

# Load background image once
try:
    background_image = get_image_background("background.jpg")
except FileNotFoundError:
    background_image = None

if dark_mode:
    # Dark mode: solid dark background, no image, light text
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] {
        background: #1e293b !important;
    }
    [data-testid="stSidebar"] {
        background: #020617 !important;
    }
    [data-testid="stAppViewContainer"] * {
        color: #e5e7eb !important;
    }
    button { color: #ffffff !important; }
    input, textarea, select {
        color: #e5e7eb !important;
        background-color: #333d4d !important;
    }
    h1, h2, h3, p, label { color: #e5e7eb !important; }
    </style>
    """, unsafe_allow_html=True)

elif animate_bg and background_image:
    # Background image ON + dark semi-transparent overlay for readability
    st.markdown(f"""
    <style>
    [data-testid="stAppViewContainer"] {{
        background: url("{background_image}") no-repeat center center fixed !important;
        background-size: cover !important;
    }}
    /* Dark overlay so text stays readable */
    [data-testid="stAppViewContainer"] > div {{
        background: rgba(0, 0, 0, 0.55);
        min-height: 100vh;
    }}
    /* Force all main content text to white over the dark overlay */
    [data-testid="stAppViewContainer"] * {{
        color: #f1f5f9 !important;
    }}
    [data-testid="stSidebar"] {{
        background: #111827 !important;
    }}
    [data-testid="stSidebar"] * {{
        color: #f9fafb !important;
    }}
    input, textarea, select {{
        background-color: rgba(255,255,255,0.1) !important;
        color: #f1f5f9 !important;
    }}
    </style>
    """, unsafe_allow_html=True)

else:
    # Default light mode, no background image
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] {
        background: #f5f7fa !important;
    }
    [data-testid="stAppViewContainer"] * {
        color: #111827 !important;
    }
    [data-testid="stSidebar"] {
        background: #111827;
    }
    [data-testid="stSidebar"] * {
        color: #f9fafb !important;
    }
    button { color: #111827 !important; }
    input, textarea, select {
        background-color: #f5f7fa !important;
        color: #111827 !important;
    }
    </style>
    """, unsafe_allow_html=True)

# ── Main Content ─────────────────────────────────────────────────────────────

st.title("Password Analyzer")
st.markdown(
    '<div class="welcome-animation">'
    'This system is designed to analyze your password strength in real-time integrating real-time feedback, entropy calculation,brute force estimation, colour-coded indicator and generate secure alternatives.<br>'
    '<small> An Optional feature to save generated passwords and passphrase is given in the sidebar which temporarily stores them , temporarily saved passwords are stored in memory vault with option to reveal but also can be deleted at any time. Passwords are never stored permanently. Session data is cleared on refresh.</small>'
    '</div>',
    unsafe_allow_html=True
)

st.markdown("---")

password_type = "text" if show_password else "password"
password = st.text_input("Enter your password:", type=password_type, key="password_input",
                          help="Type your password to see real-time analysis and suggestions.")

start_time = time.time()
live_result = analyze_password(password) if password else None
end_time = time.time()
response_time = (end_time - start_time) * 1000

st.caption(f"Response time: {response_time:.2f} ms (live analysis)")

if password:
    length_ok = len(password) >= 12
    upper_ok = any(c.isupper() for c in password)
    lower_ok = any(c.islower() for c in password)
    digit_ok = any(c.isdigit() for c in password)
    special_ok = any(c in string.punctuation for c in password)

    with st.expander("Password Checklist"):
        st.markdown(format_rule(length_ok, "At least 12 characters"), unsafe_allow_html=True)
        st.markdown(format_rule(upper_ok, "Contains uppercase letters"), unsafe_allow_html=True)
        st.markdown(format_rule(lower_ok, "Contains lowercase letters"), unsafe_allow_html=True)
        st.markdown(format_rule(digit_ok, "Contains digits"), unsafe_allow_html=True)
        st.markdown(format_rule(special_ok, "Contains special characters"), unsafe_allow_html=True)

    if live_result:
        strength = live_result["Strength"]
        score = live_result.get("Score", None)
        emoji = {"Very Weak": "🔴", "Weak": "🟠", "Medium": "🟡", "Strong": "🟢"}
        st.subheader(f"{emoji.get(strength, '')} Strength: {strength}")

        if strength in ["Very Weak", "Weak"]:
            st.error("Your password is weak. Add length, varied characters, and avoid common patterns.")
        elif strength == "Medium":
            st.warning("This password is okay, but it can be stronger.")
        else:
            st.success("Nice — this password looks strong.")

        st.markdown(f"**Entropy:** {live_result['Entropy']} bits")
        if score is not None:
            st.markdown(f"**Score:** {score}/100")
        st.markdown(f"**Estimated brute-force time:** {live_result['Bruteforce_Time']}")

        score_percent = min(max(int(score or 0), 0), 100)
        if score_percent < 40:
            bar_color = "red"
        elif score_percent < 70:
            bar_color = "orange"
        else:
            bar_color = "green"

        st.markdown(f"""
        <div style="background-color:rgba(200,200,200,0.4); border-radius:10px; overflow:hidden;">
            <div style="
                width:{score_percent}%;
                background-color:{bar_color};
                padding:10px;
                text-align:center;
                color:white;
                font-weight:bold;">
                {score_percent}%
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.subheader("Suggestions")
        for tip in live_result["Feedback"]:
            st.write(f"- {tip}")

        with st.expander("Why this matters"):
            st.write(
                "Entropy is a measure of how hard it is for attackers to guess your password. "
                "A strong password uses length and a mix of character types.")
else:
    st.info("Start typing a password above to see live feedback.")

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Analyze and Log"):
        if not password.strip():
            st.warning("Please enter a password before analyzing.")
        else:
            st.session_state.analysis = analyze_password(password)
            log_result(st.session_state.analysis["Strength"], st.session_state.analysis["Entropy"])
            st.success("Password strength logged locally.")

with col2:
    if st.button("Generate Strong Password"):
        st.session_state.generated_password = generate_strong_password(generate_length)

with col3:
    if st.button("Generate Passphrase"):
        st.session_state.generated_passphrase = generate_passphrase(word_count=passphrase_word_count)

if st.session_state.generated_password:
    st.markdown("### Generated Password")
    st.code(st.session_state.generated_password)
    copy_to_clipboard(st.session_state.generated_password, "copy_password")

if st.session_state.generated_passphrase:
    st.markdown("### Generated Passphrase")
    st.code(st.session_state.generated_passphrase)
    copy_to_clipboard(st.session_state.generated_passphrase, "copy_passphrase")
    st.caption("A passphrase is easier to remember and still strong.")

st.markdown("---")
st.subheader("Password Strength Statistics")

if show_stats:
    try:
        df = pd.read_csv("analysis_log.csv", header=None, names=["Date", "Strength", "Entropy"])
        if df.empty:
            st.info("No analysis data available yet.")
        else:
            total = len(df)
            st.metric("Total analyses logged", total)

            filter_option = st.selectbox("Filter by strength", ["All", "Very Weak", "Weak", "Medium", "Strong"])
            if filter_option != "All":
                filtered_df = df[df["Strength"] == filter_option]
            else:
                filtered_df = df

            st.dataframe(filtered_df.tail(10).reset_index(drop=True))

            summary = df["Strength"].value_counts().reindex(["Very Weak", "Weak", "Medium", "Strong"]).fillna(0)
            chart_data = pd.DataFrame({"Count": summary})
            st.bar_chart(chart_data)
            st.line_chart(chart_data)
    except FileNotFoundError:
        st.warning("No log file found yet. Analyze a password to create log data.")

st.markdown("---")






 