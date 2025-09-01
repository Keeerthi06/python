import streamlit as st
import pandas as pd
import bcrypt
import os
import re

# -------------------------------
# CSV file to store users
# -------------------------------
USER_FILE = "users.csv"

def load_users():
    if os.path.exists(USER_FILE):
        return pd.read_csv(USER_FILE)
    else:
        return pd.DataFrame(columns=["username", "password"])

def save_user(username, password):
    df = load_users()
    if username in df["username"].values:
        return False, "❌ Username already exists. Try a different one."

    # Validate username and password
    valid, message = validate_inputs(username, password)
    if not valid:
        return False, message

    # Hash the password before saving
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    new_user = pd.DataFrame([[username, hashed.decode("utf-8")]], columns=["username", "password"])
    df = pd.concat([df, new_user], ignore_index=True)
    df.to_csv(USER_FILE, index=False)
    return True, "🎉 Registration successful! You can now log in."

def validate_login(username, password):
    df = load_users()
    user_row = df[df["username"] == username]
    if user_row.empty:
        return False, "❌ Username not found. Please register first."
    else:
        stored_hash = user_row.iloc[0]["password"].encode("utf-8")
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            return True, "✅ Login successful!"
        else:
            return False, "❌ Incorrect password."

# -------------------------------
# Validation Rules
# -------------------------------
def validate_inputs(username, password):
    # Username: at least 3 characters, only letters, numbers, underscore
    if not re.match(r"^[A-Za-z0-9_]{3,}$", username):
        return False, "⚠️ Username must be at least 3 characters and contain only letters, numbers, or underscores."

    # Password: at least 6 characters, must contain uppercase, lowercase, digit
    if len(password) < 6:
        return False, "⚠️ Password must be at least 6 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "⚠️ Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "⚠️ Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "⚠️ Password must contain at least one digit."

    return True, "Valid input"

# -------------------------------
# Streamlit Page Config
# -------------------------------
st.set_page_config(page_title="🎓 Student Portal", layout="wide")

# -------------------------------
# Session State
# -------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None

# -------------------------------
# Login Page
# -------------------------------
def login_page():
    st.title("🎓 Student Login & Registration Portal")
    st.markdown("Welcome! Please login or create a new account.")

    tab1, tab2 = st.tabs(["🔓 Login", "🆕 Register"])

    with tab1:
        st.subheader("Login to Your Account")
        login_username = st.text_input("👤 Username", key="login_user")
        login_password = st.text_input("🔑 Password", type="password", key="login_pass")

        if st.button("🚀 Login"):
            valid, message = validate_login(login_username, login_password)
            if valid:
                st.success(message)
                st.session_state.logged_in = True
                st.session_state.username = login_username
                st.rerun()
            else:
                st.error(message)

    with tab2:
        st.subheader("Create a New Account")
        new_username = st.text_input("👤 Choose a Username", key="reg_user")
        new_password = st.text_input("🔐 Choose a Password", type="password", key="reg_pass")

        if st.button("📝 Register"):
            success, message = save_user(new_username, new_password)
            if success:
                st.success(message)
            else:
                st.error(message)

# -------------------------------
# Dashboard Page
# -------------------------------
def dashboard_page():
    st.sidebar.title(f"👋 Welcome, {st.session_state.username}")
    menu = st.sidebar.radio("📌 Navigation", ["🏠 Home", "📊 My Dashboard", "⚙️ Settings", "🚪 Logout"])

    if menu == "🏠 Home":
        st.title("🏠 Home")
        st.write("This is the home page of the Student Portal. Explore using the sidebar!")

    elif menu == "📊 My Dashboard":
        st.title("📊 Student Dashboard")
        st.info("Here you could show grades, assignments, or announcements.")
        st.bar_chart({"Math": [80], "Science": [90], "English": [70], "History": [85]})

    elif menu == "⚙️ Settings":
        st.title("⚙️ Account Settings")
        st.warning("Feature under construction 🚧")
        st.write("In the future, you can update your profile or reset your password here.")

    elif menu == "🚪 Logout":
        st.session_state.logged_in = False
        st.session_state.username = None
        st.success("✅ You have been logged out.")
        st.rerun()

# -------------------------------
# Run the App
# -------------------------------
if st.session_state.logged_in:
    dashboard_page()
else:
    login_page()
