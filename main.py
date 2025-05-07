import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

DATA_FILE = "data.json"
KEY = b'W9V5nGtQSe2mRGOY-iRJR7gWxXpTaVuU0ZyNsOF1xao='

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE,'r') as file:
            return json.load(file)
    return {}

def save_data(data):                
    with open(DATA_FILE,'w') as file:
        json.dump(data ,file) # Write Python object to a JSON file

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

cipher = Fernet(KEY)
stored_data = load_data()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

st.title("🔐 Simple Secure Note App")

menu = ["Home","Sign Up","Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

if choice == "Sign Up":
    st.subheader("📝 Create New Account")
    new_user = st.text_input("New Username")
    new_passkey = st.text_input("New Passkey", type="password")    

    if new_user and new_passkey:
        hashed = hash_passkey(new_passkey)
        if new_user not in stored_data:
            stored_data[new_user] = []
        stored_data[new_user].append({
            " passkey": hashed
        })
        save_data(stored_data)
        st.success("✅ Account created! Now login.")
    else:
        st.warning("Please enter both fields.")    


if choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Login"):
        if username and passkey:
            entries = stored_data.get(username, [])
            hashed = hash_passkey(passkey)
            if any(entry["passkey"] == hashed for entry in entries):
                st.success("✅ Login successful!")
                st.session_state.logged_in = True
                st.session_state.username = username
            else:
                st.error("❌ Incorrect username or passkey.")
        else:
            st.warning("Please enter both username and passkey.")

elif choice == "Store Data":
    if st.session_state.logged_in:
        st.subheader("📥 Store Data")
        text = st.text_area("Enter Text to Encrypt")
        passkey = st.text_input("Confirm Passkey", type="password")

        if st.button("Save"):
            if text and passkey:
                encrypted = cipher.encrypt(text.encode()).decode()
                hashed = hash_passkey(passkey)

                username = st.session_state.username
                if username not in stored_data:
                    stored_data[username] = []

                stored_data[username].append({
                    "encrypted": encrypted,
                    "passkey": hashed
                })
                save_data(stored_data)
                st.success("✅ Data saved!")
                st.code(encrypted)
            else:
                st.warning("Please fill all fields.")
    else:
        st.warning("⚠️ Please login first.")

elif choice == "Retrieve Data":
    if st.session_state.logged_in:
        st.subheader("🔓 Retrieve Data")
        encrypted = st.text_area("Paste Encrypted Text")
        passkey = st.text_input("Confirm Passkey", type="password")

        if st.button("Decrypt"):
            if encrypted and passkey:
                username = st.session_state.username
                entries = stored_data.get(username, [])
                hashed = hash_passkey(passkey)
                for entry in entries:
                    if entry["encrypted"] == encrypted and entry["passkey"] == hashed:
                        try:
                            decrypted = cipher.decrypt(encrypted.encode()).decode()
                            st.success("✅ Decrypted Text:")
                            st.code(decrypted)
                            break
                        except:
                            st.error("❌ Decryption failed.")
                            break
                else:
                    st.error("❌ No matching data found.")
            else:
                st.warning("Please fill all fields.")
    else:
        st.warning("⚠️ Please login first.")





    