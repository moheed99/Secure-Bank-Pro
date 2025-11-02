import streamlit as st
import bcrypt
import hashlib
import re
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import secrets
import base64

# Page config
st.set_page_config(
    page_title="SecureBank Pro",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional look
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    .main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 0;
    }
    
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    .auth-container {
        background: white;
        padding: 3rem;
        border-radius: 20px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        max-width: 450px;
        margin: 2rem auto;
    }
    
    .dashboard-card {
        background: white;
        padding: 2rem;
        border-radius: 15px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        margin-bottom: 1.5rem;
        transition: transform 0.3s ease;
    }
    
    .dashboard-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 15px 40px rgba(0,0,0,0.15);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin: 0.5rem 0;
    }
    
    .metric-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }
    
    h1, h2, h3 {
        color: #2d3748;
        font-weight: 700;
    }
    
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        font-size: 1rem;
        font-weight: 600;
        border-radius: 8px;
        width: 100%;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
    }
    
    .sidebar .sidebar-content {
        background: white;
    }
    
    .log-entry {
        background: #f7fafc;
        padding: 1rem;
        border-left: 4px solid #667eea;
        margin: 0.5rem 0;
        border-radius: 4px;
    }
    
    .success-msg {
        background: #c6f6d5;
        color: #22543d;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .error-msg {
        background: #fed7d7;
        color: #742a2a;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .info-box {
        background: #bee3f8;
        color: #2c5282;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'session_token' not in st.session_state:
    st.session_state.session_token = None

# File paths
DATA_DIR = "secure_data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
LOGS_FILE = os.path.join(DATA_DIR, "audit_logs.json")
ENCRYPTION_KEY_FILE = os.path.join(DATA_DIR, "encryption.key")

# Create data directory
os.makedirs(DATA_DIR, exist_ok=True)

# Encryption setup
def get_encryption_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Helper functions
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def log_activity(username, action, details=""):
    logs = []
    if os.path.exists(LOGS_FILE):
        with open(LOGS_FILE, 'r') as f:
            logs = json.load(f)
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "action": action,
        "details": details,
        "ip": "127.0.0.1"  # In real app, get actual IP
    }
    logs.append(log_entry)
    
    with open(LOGS_FILE, 'w') as f:
        json.dump(logs, f, indent=2)

def validate_password(password):
    """Enforce strong password rules"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def encrypt_data(data):
    """Encrypt sensitive data"""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return "***ENCRYPTED***"

def sanitize_input(text):
    """Basic input sanitization"""
    # Remove potential SQL injection and XSS patterns
    dangerous_patterns = ['<script>', 'javascript:', 'onerror=', 'onclick=', 
                         'DROP TABLE', 'INSERT INTO', 'DELETE FROM', '--', ';']
    
    text_lower = text.lower()
    for pattern in dangerous_patterns:
        if pattern.lower() in text_lower:
            return None
    return text

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

# Authentication UI
def show_login_page():
    st.markdown("<div class='auth-container'>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("# 🔐 SecureBank Pro")
        st.markdown("### Professional FinTech Platform")
    
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])
    
    with tab1:
        st.markdown("#### Welcome Back!")
        username = st.text_input("Username", key="login_username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")
        
        if st.button("Login", key="login_btn"):
            if not username or not password:
                st.error("⚠️ Please fill in all fields")
                log_activity("anonymous", "Failed login attempt", "Empty credentials")
                return
            
            # Sanitize input
            username = sanitize_input(username)
            if username is None:
                st.error("⚠️ Invalid input detected")
                log_activity("anonymous", "Malicious input detected", "Login attempt")
                return
            
            users = load_users()
            if username in users and verify_password(password, users[username]['password']):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.session_token = generate_session_token()
                log_activity(username, "Login", "Successful login")
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password")
                log_activity(username or "anonymous", "Failed login", "Invalid credentials")
    
    with tab2:
        st.markdown("#### Create New Account")
        new_username = st.text_input("Username", key="reg_username", placeholder="Choose a username")
        new_email = st.text_input("Email", key="reg_email", placeholder="your@email.com")
        new_password = st.text_input("Password", type="password", key="reg_password", placeholder="Create a strong password")
        confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm", placeholder="Re-enter password")
        
        if st.button("Register", key="reg_btn"):
            if not new_username or not new_email or not new_password:
                st.error("⚠️ Please fill in all fields")
                return
            
            # Sanitize inputs
            new_username = sanitize_input(new_username)
            new_email = sanitize_input(new_email)
            
            if new_username is None or new_email is None:
                st.error("⚠️ Invalid input detected")
                log_activity("anonymous", "Malicious input detected", "Registration attempt")
                return
            
            # Validate email
            if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                st.error("⚠️ Invalid email format")
                return
            
            # Validate password
            is_valid, message = validate_password(new_password)
            if not is_valid:
                st.error(f"⚠️ {message}")
                return
            
            if new_password != confirm_password:
                st.error("⚠️ Passwords do not match")
                return
            
            users = load_users()
            if new_username in users:
                st.error("⚠️ Username already exists")
                return
            
            # Create new user
            users[new_username] = {
                'password': hash_password(new_password),
                'email': encrypt_data(new_email),
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'profile': {
                    'full_name': '',
                    'phone': '',
                    'balance': 10000.00
                }
            }
            save_users(users)
            log_activity(new_username, "Registration", "New user registered")
            st.success("✅ Registration successful! Please login.")
    
    st.markdown("</div>", unsafe_allow_html=True)

# Dashboard UI
def show_dashboard():
    # Sidebar
    with st.sidebar:
        st.markdown("### 👤 User Profile")
        st.markdown(f"**{st.session_state.username}**")
        st.markdown("---")
        
        menu = st.radio(
            "Navigation",
            ["🏠 Dashboard", "💳 Transactions", "👤 Profile", "🔒 Encryption Tool", "📊 Activity Logs", "📁 File Upload"],
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        
        if st.button("🚪 Logout"):              # ← 8 spaces
            import time                         # ← 12 spaces
            username = st.session_state.username # ← 12 spaces
          
    log_activity(username, "Logout", "User logged out")
    
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.session_token = None
    
    st.success("✅ Logout successful! Redirecting to login page...")
    time.sleep(1)
    st.rerun()
    
    # Main content
    users = load_users()
    user_data = users[st.session_state.username]
    
    if menu == "🏠 Dashboard":
        st.title("📊 Dashboard Overview")
        
        # Metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"""
            <div class='metric-card'>
                <div class='metric-label'>Account Balance</div>
                <div class='metric-value'>₨{user_data['profile']['balance']:,.2f}</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class='metric-card'>
                <div class='metric-label'>Account Status</div>
                <div class='metric-value'>✓ Active</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class='metric-card'>
                <div class='metric-label'>Security Level</div>
                <div class='metric-value'>🔒 High</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Quick Actions
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.markdown("### ⚡ Quick Actions")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("💸 Send Money", use_container_width=True):
                st.info("Navigate to Transactions to send money")
        
        with col2:
            if st.button("📝 Update Profile", use_container_width=True):
                st.info("Navigate to Profile to update details")
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Recent Activity
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.markdown("### 📜 Recent Activity")
        if os.path.exists(LOGS_FILE):
            with open(LOGS_FILE, 'r') as f:
                logs = json.load(f)
            user_logs = [log for log in logs if log['username'] == st.session_state.username][-5:]
            
            for log in reversed(user_logs):
                st.markdown(f"""
                <div class='log-entry'>
                    <strong>{log['action']}</strong> - {log['timestamp']}<br>
                    <small>{log['details']}</small>
                </div>
                """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    
    elif menu == "💳 Transactions":
        st.title("💳 Financial Transactions")
        
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.markdown("### 💸 Send Money")
        
        recipient = st.text_input("Recipient Username", placeholder="Enter recipient username")
        amount = st.number_input("Amount (₨)", min_value=1.0, max_value=float(user_data['profile']['balance']), step=100.0)
        description = st.text_area("Description", placeholder="Payment description")
        
        if st.button("Send Money"):
            if not recipient or amount <= 0:
                st.error("⚠️ Please fill in all fields correctly")
                return
            
            # Sanitize input
            recipient = sanitize_input(recipient)
            description = sanitize_input(description)
            
            if recipient is None or description is None:
                st.error("⚠️ Invalid input detected")
                log_activity(st.session_state.username, "Malicious input", "Transaction attempt")
                return
            
            if recipient not in users:
                st.error("⚠️ Recipient not found")
                return
            
            if recipient == st.session_state.username:
                st.error("⚠️ Cannot send money to yourself")
                return
            
            # Process transaction
            users[st.session_state.username]['profile']['balance'] -= amount
            users[recipient]['profile']['balance'] += amount
            save_users(users)
            
            log_activity(st.session_state.username, "Transaction", 
                        f"Sent ₨{amount} to {recipient} - {description}")
            
            st.success(f"✅ Successfully sent ₨{amount} to {recipient}")
            st.rerun()
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    elif menu == "👤 Profile":
        st.title("👤 User Profile")
        
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.markdown("### 📝 Update Profile Information")
        
        full_name = st.text_input("Full Name", value=user_data['profile'].get('full_name', ''))
        phone = st.text_input("Phone Number", value=user_data['profile'].get('phone', ''))
        email_display = st.text_input("Email", value=decrypt_data(user_data['email']), disabled=True)
        
        if st.button("Update Profile"):
            # Sanitize inputs
            full_name = sanitize_input(full_name)
            phone = sanitize_input(phone)
            
            if full_name is None or phone is None:
                st.error("⚠️ Invalid input detected")
                return
            
            # Validate phone
            if phone and not re.match(r"^\+?[\d\s-]{10,}$", phone):
                st.error("⚠️ Invalid phone number format")
                return
            
            users[st.session_state.username]['profile']['full_name'] = full_name
            users[st.session_state.username]['profile']['phone'] = phone
            save_users(users)
            
            log_activity(st.session_state.username, "Profile Update", "Profile information updated")
            st.success("✅ Profile updated successfully!")
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Change Password
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.markdown("### 🔐 Change Password")
        
        old_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password", key="new_pass")
        confirm_new = st.text_input("Confirm New Password", type="password")
        
        if st.button("Change Password"):
            if not verify_password(old_password, user_data['password']):
                st.error("⚠️ Current password is incorrect")
                return
            
            is_valid, message = validate_password(new_password)
            if not is_valid:
                st.error(f"⚠️ {message}")
                return
            
            if new_password != confirm_new:
                st.error("⚠️ Passwords do not match")
                return
            
            users[st.session_state.username]['password'] = hash_password(new_password)
            save_users(users)
            
            log_activity(st.session_state.username, "Password Change", "Password changed successfully")
            st.success("✅ Password changed successfully!")
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    elif menu == "🔒 Encryption Tool":
        st.title("🔒 Data Encryption Tool")
        
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔐 Encrypt", "🔓 Decrypt"])
        
        with tab1:
            st.markdown("### Encrypt Sensitive Data")
            plain_text = st.text_area("Enter text to encrypt", placeholder="Enter sensitive data...")
            
            if st.button("Encrypt"):
                if plain_text:
                    encrypted = encrypt_data(plain_text)
                    st.code(encrypted, language="text")
                    log_activity(st.session_state.username, "Encryption", "Data encrypted")
                    st.success("✅ Data encrypted successfully!")
                else:
                    st.warning("⚠️ Please enter text to encrypt")
        
        with tab2:
            st.markdown("### Decrypt Encrypted Data")
            encrypted_text = st.text_area("Enter encrypted text", placeholder="Paste encrypted data...")
            
            if st.button("Decrypt"):
                if encrypted_text:
                    try:
                        decrypted = decrypt_data(encrypted_text)
                        st.success("Decrypted text:")
                        st.code(decrypted, language="text")
                        log_activity(st.session_state.username, "Decryption", "Data decrypted")
                    except Exception as e:
                        st.error("⚠️ Invalid encrypted data or decryption failed")
                        log_activity(st.session_state.username, "Decryption Failed", "Invalid data")
                else:
                    st.warning("⚠️ Please enter encrypted text")
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    elif menu == "📊 Activity Logs":
        st.title("📊 Activity Logs")
        
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.markdown("### 📜 Your Activity History")
        
        if os.path.exists(LOGS_FILE):
            with open(LOGS_FILE, 'r') as f:
                logs = json.load(f)
            
            user_logs = [log for log in logs if log['username'] == st.session_state.username]
            
            st.info(f"📈 Total activities: {len(user_logs)}")
            
            for log in reversed(user_logs[-20:]):  # Show last 20 logs
                st.markdown(f"""
                <div class='log-entry'>
                    <strong>{log['action']}</strong><br>
                    📅 {log['timestamp']} | 🌐 {log['ip']}<br>
                    📝 {log['details']}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No activity logs found")
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    elif menu == "📁 File Upload":
        st.title("📁 Secure File Upload")
        
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.markdown("### 📤 Upload Documents")
        
        st.info("🔒 Only PDF, PNG, JPG, and JPEG files are allowed (Max 5MB)")
        
        uploaded_file = st.file_uploader("Choose a file", type=['pdf', 'png', 'jpg', 'jpeg'])
        
        if uploaded_file is not None:
            file_details = {
                "Filename": uploaded_file.name,
                "FileType": uploaded_file.type,
                "FileSize": f"{uploaded_file.size / 1024:.2f} KB"
            }
            
            # Validate file size (5MB limit)
            if uploaded_file.size > 5 * 1024 * 1024:
                st.error("⚠️ File size exceeds 5MB limit")
                log_activity(st.session_state.username, "File Upload Failed", f"File too large: {uploaded_file.name}")
            else:
                st.success("✅ File validated successfully!")
                st.json(file_details)
                
                if st.button("Confirm Upload"):
                    # In real app, save the file securely
                    log_activity(st.session_state.username, "File Upload", 
                               f"Uploaded {uploaded_file.name} ({file_details['FileSize']})")
                    st.success(f"✅ File '{uploaded_file.name}' uploaded successfully!")
        
        st.markdown("</div>", unsafe_allow_html=True)

# Main app
def main():
    if not st.session_state.logged_in:
        show_login_page()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()
