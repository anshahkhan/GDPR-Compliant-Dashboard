import streamlit as st
import sqlite3
import os
from datetime import datetime, timedelta
from hashlib import sha256
from cryptography.fernet import Fernet, InvalidToken
import pandas as pd
from streamlit_autorefresh import st_autorefresh

DB_PATH = "hospital.db"
FERNET_KEY_FILE = "fernet.key"



# -------------------------------------
# SYSTEM UPTIME TRACKING
# -------------------------------------
if "app_start_time" not in st.session_state:
    st.session_state.app_start_time = datetime.now()


def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()
# -------------------------------
# HELPERS: Fernet key management
# -------------------------------
def ensure_fernet_key():
    """Create a local Fernet key file if it doesn't exist and return the key (bytes)."""
    if not os.path.exists(FERNET_KEY_FILE):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(key)
        return key
    with open(FERNET_KEY_FILE, "rb") as f:
        return f.read()

# Load key at module init (safe for demo; in production keep this in secure vault)
FERNET_KEY = ensure_fernet_key()
f_fernet = Fernet(FERNET_KEY)

# -------------------------------
# DATABASE INITIALIZATION
# -------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    # Patients table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            contact TEXT,
            diagnosis TEXT,
            anonymized_name TEXT,
            anonymized_contact TEXT,
            date_added TEXT
        )
    """)

    # --- Add missing columns dynamically ---

    # Get existing columns
    cur.execute("PRAGMA table_info(patients)")
    columns = [col[1] for col in cur.fetchall()]

    # Add key_id column
    if "key_id" not in columns:
        cur.execute("ALTER TABLE patients ADD COLUMN key_id INTEGER DEFAULT 1")

    # Add reversible anonymization columns
    if "reversible_anon_name" not in columns:
        cur.execute("ALTER TABLE patients ADD COLUMN reversible_anon_name TEXT")

    if "reversible_anon_contact" not in columns:
        cur.execute("ALTER TABLE patients ADD COLUMN reversible_anon_contact TEXT")

    # Logs table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            role TEXT,
            action TEXT,
            timestamp TEXT,
            details TEXT
        )
    """)

    # Config table (retention policy)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            k TEXT PRIMARY KEY,
            v TEXT
        )
    """)
    cur.execute("SELECT v FROM config WHERE k='retention_days'")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO config (k, v) VALUES (?, ?)", ("retention_days", "365"))

    # Fernet keys table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS fernet_keys (
            key_id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_value TEXT NOT NULL,
            created_at TEXT
        )
    """)

    # Insert default encryption key
    cur.execute("SELECT COUNT(*) FROM fernet_keys")
    if cur.fetchone()[0] == 0:
        key = Fernet.generate_key()
        cur.execute(
            "INSERT INTO fernet_keys (key_value, created_at) VALUES (?, ?)",
            (key.decode(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

    # Default users
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin')",
                    (hash_password("admin123"),))
        cur.execute("INSERT INTO users (username, password, role) VALUES ('bob', ?, 'doctor')",
                    (hash_password("doc123"),))
        cur.execute("INSERT INTO users (username, password, role) VALUES ('alice', ?, 'receptionist')",
                    (hash_password("rec123"),))

    conn.commit()
    conn.close()



init_db()

# -------------------------------
# UTILITY FUNCTIONS
# -------------------------------



def db_connect():
    return sqlite3.connect(DB_PATH)

def get_system_uptime():
    start = st.session_state.app_start_time
    now = datetime.now()
    delta = now - start
    return str(delta).split('.')[0]  # clean format (HH:MM:SS)


def log_action(user_id, role, action, details=""):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs (user_id, role, action, timestamp, details)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, role, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), details))
    conn.commit()
    conn.close()

def mask_contact(contact):
    if not contact:
        return ""
    contact = str(contact)
    return "XXX-XXX-" + contact[-4:]

def anonymize_name(name):
    if not name:
        return ""
    return "ANON_" + sha256(name.encode()).hexdigest()[:6]

def login_user(username, password):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT user_id, role FROM users WHERE username=? AND password=?",
            (username, hash_password(password)))
    user = cur.fetchone()
    conn.close()
    return user

def encrypt_value(value: str):
    if value is None:
        return None
    key_id, fernet = get_latest_key()
    encrypted = fernet.encrypt(value.encode())
    return encrypted, key_id  

def decrypt_value(encrypted_value, key_id):
    if encrypted_value is None:
        return ""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT key_value FROM fernet_keys WHERE key_id=?", (key_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return "[missing key]"
    fernet = Fernet(row[0].encode())
    try:
        return fernet.decrypt(encrypted_value).decode()
    except InvalidToken:
        return "[decryption error]"


# Fetch the latest key for encryption
def get_latest_key():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT key_id, key_value FROM fernet_keys ORDER BY key_id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if row:
        key_id, key_value = row
        return key_id, Fernet(key_value.encode())
    # If no key exists, generate one
    key_id, fernet = rotate_fernet_key()
    return key_id, fernet

# Rotate key (adds new key to fernet_keys table)
def rotate_fernet_key():
    new_key = Fernet.generate_key()
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO fernet_keys (key_value, created_at) VALUES (?, ?)",
        (new_key.decode(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    cur.execute("SELECT key_id FROM fernet_keys ORDER BY key_id DESC LIMIT 1")
    key_id = cur.fetchone()[0]
    conn.close()
    return key_id, Fernet(new_key)

# -------------------------------
# DATA RETENTION
# -------------------------------
def get_retention_days():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT v FROM config WHERE k='retention_days'")
    row = cur.fetchone()
    conn.close()
    return int(row[0]) if row else 365

def set_retention_days(days: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("REPLACE INTO config (k, v) VALUES (?, ?)", ("retention_days", str(days)))
    conn.commit()
    conn.close()

def retention_cleanup(days: int):
    """Delete patients older than 'days' based on date_added."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = db_connect()
    cur = conn.cursor()
    # Log details: how many rows will be removed
    cur.execute("SELECT COUNT(*) FROM patients WHERE date_added < ?", (cutoff,))
    count = cur.fetchone()[0]
    cur.execute("DELETE FROM patients WHERE date_added < ?", (cutoff,))
    conn.commit()
    conn.close()
    return count

# -------------------------------
# DASHBOARD PAGES
# -------------------------------
def show_consent_banner():
    # GDPR consent banner displayed before login
    if "consent_given" not in st.session_state:
        st.session_state.consent_given = False

    if not st.session_state.consent_given:
        st.info("This app processes personal data for educational/demo purposes. Please read our Privacy Notice.")
        cols = st.columns([6,1])
        with cols[0]:
            consent = st.checkbox("I have read and I consent to data processing under the Privacy Notice.", key="consent_checkbox")
        with cols[1]:
            if st.button("I consent"):
                if st.session_state.get("consent_checkbox", False):
                    st.session_state.consent_given = True
                    # Log consent (user_id=0 because not logged in yet)
                    log_action(0, "anonymous", "consent_given", "User accepted privacy notice")
                    st.rerun()
                else:
                    st.warning("Please tick the checkbox first to consent.")
        return st.session_state.consent_given
    return True

def dashboard():
    user_id = st.session_state.user_id
    role = st.session_state.role

    st.title("🏥 GDPR-Compliant Hospital Privacy Dashboard")
    st.sidebar.write(f"**Logged in as:** {role}")
    st.sidebar.write("System uptime: Active")

    menu = ["Home", "View Patients"]
    if role in ["admin", "receptionist"]:
        menu.append("Add Patient")
    if role in ["admin"]:
        menu.append("Manage Patients")
    if role == "admin":
        menu += ["Anonymize Data", "Audit Logs", "Retention Settings", "Fernet Keys", "User Management", "Backup & Restore"]
    menu.append("Logout")

    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.role = None
        st.rerun()

        # Home
    if choice == "Home":
        st.subheader("📊 System Overview Dashboard")
        if role == "admin":
            # Fetch data
            conn = db_connect()
            df_patients = pd.read_sql_query(
                "SELECT patient_id, diagnosis, date_added FROM patients", conn
            )
            df_logs = pd.read_sql_query(
                "SELECT action, timestamp, role FROM logs ORDER BY timestamp DESC", conn
            )
            conn.close()

            # -----------------------------
            # TOP KPI CARDS
            # -----------------------------
            total_patients = len(df_patients)
            total_logs = len(df_logs)
            unique_actions = df_logs["action"].nunique() if not df_logs.empty else 0
            today = datetime.now().date()
            new_today = df_patients[df_patients["date_added"] == str(today)]

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Patients", total_patients)
            col2.metric("New Patients Today", len(new_today))
            col3.metric("Total Audit Logs", total_logs)
            col4.metric("Unique System Actions", unique_actions)

            st.markdown("---")

            # -----------------------------
            # PATIENTS PER DAY CHART
            # -----------------------------
            st.subheader("📅 Patients Added Per Day (Trend)")

            if not df_patients.empty:
                try:
                    df_patients["date"] = pd.to_datetime(df_patients["date_added"])
                    patients_per_day = df_patients.groupby(df_patients["date"]).size()
                    st.line_chart(patients_per_day)
                except Exception:
                    st.warning("Could not generate patient trend chart.")
            else:
                st.info("No patient records found.")

            st.markdown("---")

            # -----------------------------
            # MOST COMMON ACTIONS (BAR CHART)
            # -----------------------------
            st.subheader("🛡 Most Common System Actions (Audit Logs)")

            if not df_logs.empty:
                action_counts = df_logs["action"].value_counts()
                st.bar_chart(action_counts)
            else:
                st.info("No logs yet to display.")

            st.markdown("---")

            # -----------------------------
            # ROLE ACTIVITY PIE CHART
            # -----------------------------
            st.subheader("👥 Activity Distribution by Role")

            if not df_logs.empty:
                try:
                    role_counts = df_logs["role"].value_counts()
                    st.bar_chart(role_counts)  # Simplified pie-style using bar chart
                except Exception:
                    pass
            else:
                st.info("No role activity yet.")

            st.markdown("---")

            # -----------------------------
            # LATEST ACTIVITY TABLE
            # -----------------------------
            st.subheader("📝 Latest Activity")

            if not df_logs.empty:
                st.dataframe(df_logs.head(10))
            else:
                st.info("No recent activity to display.")

                # -------------------------------------
        # DASHBOARD FOOTER
        # -------------------------------------
        st.markdown("---")
        st.write("### 🕒 System Information")

        if "dashboard_uptime" not in st.session_state:
            st.session_state.dashboard_uptime = st.empty()
        st.session_state.dashboard_uptime.metric("System Uptime", get_system_uptime())

        st.write(f"**Last Synchronization:** {st.session_state.last_sync}")
        st.write(f"**Current Server Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")



    # View Patients
    elif choice == "View Patients":
        conn = db_connect()
        df = pd.read_sql_query("""
            SELECT patient_id, name, contact, 
                anonymized_name, anonymized_contact, diagnosis, date_added 
            FROM patients
        """, conn)
        conn.close()

        if role == "doctor":
            st.dataframe(df[["patient_id", "anonymized_name", "anonymized_contact", "diagnosis", "date_added"]])
        elif role == "receptionist":
            st.dataframe(df[["patient_id", "diagnosis", "date_added"]])
        elif role == "admin":
            st.write("Admin view — encrypted fields are shown. Use 'Decrypt selected' to reveal values.")
            st.dataframe(df[["patient_id", "name", "contact", "anonymized_name", "anonymized_contact", "diagnosis", "date_added"]])

            # Decrypt selected patient
            pid_to_decrypt = st.number_input("Enter Patient ID to decrypt", min_value=1, step=1)
            if st.button("Decrypt selected"):
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("SELECT name, contact, key_id FROM patients WHERE patient_id=?", (pid_to_decrypt,))
                row = cur.fetchone()
                conn.close()

                if row:
                    decrypted_name = decrypt_value(row[0], row[2])
                    decrypted_contact = decrypt_value(row[1], row[2])
                    st.success(f"Decrypted name: {decrypted_name}")
                    st.success(f"Decrypted contact: {decrypted_contact}")
                    log_action(user_id, role, "decrypt_patient", f"patient_id={pid_to_decrypt}")
                else:
                    st.error("Patient not found.")

                log_action(user_id, role, "view_patients")


 # Add Patient
    elif choice == "Add Patient":
        st.subheader("Add Patient")
        name = st.text_input("Name (original will be encrypted later)")
        contact = st.text_input("Contact (original will be encrypted later)")
        diagnosis = st.text_input("Diagnosis")

        if st.button("Save"):
            conn = db_connect()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO patients 
                    (name, contact, name, contact, 
                    diagnosis, anonymized_name, anonymized_contact, 
                    date_added, key_id)
                VALUES (?, ?, NULL, NULL, ?, NULL, NULL, ?, NULL)
            """, (
                name, contact, diagnosis,
                datetime.now().strftime("%Y-%m-%d")
            ))
            conn.commit()
            conn.close()

            st.success("Patient added (original data stored temporarily).")
            log_action(user_id, role, "add_patient_original", f"name={name}")



    # ----------------------------------------
# Manage Patients (Edit / Delete)
# ----------------------------------------
    elif choice == "Manage Patients" and role in ["admin", "receptionist"]:
        st.subheader("Manage Patients (Edit / Delete)")
        conn = db_connect()
        df = pd.read_sql_query("SELECT patient_id, diagnosis, anonymized_name, anonymized_contact, date_added FROM patients", conn)
        conn.close()
        st.dataframe(df)

        pid = st.number_input("Enter Patient ID", min_value=1, step=1)

        action = st.selectbox("Action", ["Edit Diagnosis", "Delete Patient"])

        if action == "Edit Diagnosis":
            new_diag = st.text_input("New Diagnosis")
            if st.button("Save Changes"):
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("UPDATE patients SET diagnosis=? WHERE patient_id=?", (new_diag, pid))
                conn.commit()
                conn.close()
                st.success("Diagnosis updated.")
                log_action(user_id, role, "edit_patient", f"patient_id={pid}")

        elif action == "Delete Patient":
            if st.button("Delete Now"):
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("DELETE FROM patients WHERE patient_id=?", (pid,))
                conn.commit()
                conn.close()
                st.error("Patient deleted permanently.")
                log_action(user_id, role, "delete_patient", f"patient_id={pid}")


    # ---------------------------------------------------
    # USER MANAGEMENT (ADMIN ONLY)
    # ---------------------------------------------------
    elif choice == "User Management" and role == "admin":
        st.subheader("User Management (Admin Only)")

        # Display existing users
        conn = db_connect()
        df_users = pd.read_sql_query("SELECT user_id, username, role FROM users", conn)
        conn.close()

        st.write("### Existing Users")
        st.dataframe(df_users)

        # -------------------------------
        # ADD NEW USER
        # -------------------------------
        st.write("### ➕ Add New User")

        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        new_role = st.selectbox("New User Role", ["admin", "doctor", "receptionist"])

        if st.button("Create User"):
            if not new_username or not new_password:
                st.error("Username and password are required.")
            else:
                try:
                    conn = db_connect()
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO users (username, password, role)
                        VALUES (?, ?, ?)
                    """, (new_username, hash_password(new_password), new_role))
                    conn.commit()
                    conn.close()
                    st.success(f"User '{new_username}' created successfully.")
                    log_action(user_id, role, "add_user", f"username={new_username}")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("Username already exists!")

        st.markdown("---")
        st.write("### ✏️ Edit or ❌ Delete Existing Users")

        # -------------------------------
        # SELECT USER FOR EDIT / DELETE
        # -------------------------------
        user_ids = df_users["user_id"].tolist()
        selected_user_id = st.selectbox("Select User ID", user_ids)

        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT username, role FROM users WHERE user_id=?", (selected_user_id,))
        u = cur.fetchone()
        conn.close()

        if u:
            current_username, current_role = u

            st.write(f"Selected User: **{current_username}** (Role: {current_role})")
            action = st.selectbox("Action", ["Edit User", "Delete User"])

            # -------------------------------
            # EDIT USER
            # -------------------------------
            if action == "Edit User":
                st.write("### Edit User Details")

                edit_username = st.text_input("New Username", value=current_username)
                edit_password = st.text_input("New Password (leave blank to keep same)", type="password")
                edit_role = st.selectbox("New Role", ["admin", "doctor", "receptionist"], index=["admin", "doctor", "receptionist"].index(current_role))

                if st.button("Save Changes"):
                    conn = db_connect()
                    cur = conn.cursor()

                    # Update username & role
                    cur.execute("UPDATE users SET username=?, role=? WHERE user_id=?",
                                (edit_username, edit_role, selected_user_id))

                    # Update password only if changed
                    if edit_password.strip():
                        cur.execute("UPDATE users SET password=? WHERE user_id=?",
                                    (hash_password(edit_password), selected_user_id))

                    conn.commit()
                    conn.close()

                    st.success("User updated successfully.")
                    log_action(user_id, role, "edit_user", f"user_id={selected_user_id}")
                    st.rerun()

            # -------------------------------
            # DELETE USER
            # -------------------------------
            elif action == "Delete User":
                st.write("### ⚠️ Delete User")
                st.warning("This action is permanent and cannot be undone.")

                if st.button("Delete User Now"):
                    conn = db_connect()
                    cur = conn.cursor()
                    cur.execute("DELETE FROM users WHERE user_id=?", (selected_user_id,))
                    conn.commit()
                    conn.close()

                    st.error(f"User '{current_username}' deleted permanently.")
                    log_action(user_id, role, "delete_user", f"user_id={selected_user_id}")
                    st.rerun()


#Anonymize
    elif choice == "Anonymize Data" and role == "admin":
        st.subheader("🔐 Encrypt + Anonymize All Records")

        if st.button("Encrypt + Anonymize All Records"):
            conn = db_connect()
            cur = conn.cursor()

            cur.execute("SELECT patient_id, name, contact FROM patients")
            rows = cur.fetchall()

            for pid, name, contact in rows:

                # Encrypt the original fields themselves
                enc_name, key_id = encrypt_value(name) if name else (None, None)
                enc_contact, key_id2 = encrypt_value(contact) if contact else (None, None)
                final_key_id = key_id or key_id2

                # Anonymize values
                anon_name = anonymize_name(name) if name else ""
                anon_contact = mask_contact(contact) if contact else ""

                # Update DB: overwrite original name/contact
                cur.execute("""
                    UPDATE patients
                    SET name=?, contact=?, key_id=?,
                        anonymized_name=?, anonymized_contact=?
                    WHERE patient_id=?
                """, (
                    enc_name, enc_contact, final_key_id,
                    anon_name, anon_contact,
                    pid
                ))

            conn.commit()
            conn.close()

            st.success("✔ All records ENCRYPTED + ANONYMIZED. Original data replaced.")
            log_action(user_id, role, "encrypt_anonymize_all", "Admin applied full protection")





# -------------------------------
# Backup & Restore (Admin) with Multi-Key Support
# -------------------------------
    elif choice == "Backup & Restore" and role == "admin":
        st.subheader("Backup & Restore Database Tables (Multi-Key Safe)")

        backup_folder = "backups"
        os.makedirs(backup_folder, exist_ok=True)

        conn = db_connect()
        cur = conn.cursor()

        # Get all user tables (excluding logs/config/fernet_keys)
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        all_tables = [t[0] for t in cur.fetchall() if t[0] not in ["logs", "config", "fernet_keys"]]
        conn.close()

        st.markdown("### 🔹 Backup Table")
        table_to_backup = st.selectbox("Select table to backup", all_tables)

        if st.button("Create Backup"):
            conn = db_connect()
            df = pd.read_sql_query(f"SELECT * FROM {table_to_backup}", conn)
            conn.close()

            if df.empty:
                st.warning("Table is empty, nothing to backup.")
            else:
                # Include key_id info per record for tables with encryption
                if "key_id" in df.columns:
                    # Keep key_id column so we can restore with correct keys
                    df_backup = df.copy()
                else:
                    df_backup = df

                csv_bytes = df_backup.to_csv(index=False).encode()

                # Encrypt using latest key
                key_id, fernet = get_latest_key()
                encrypted_bytes = fernet.encrypt(csv_bytes)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_filename = f"{table_to_backup}_backup_{timestamp}_key{key_id}.csv.enc"
                backup_path = os.path.join(backup_folder, backup_filename)
                with open(backup_path, "wb") as f:
                    f.write(encrypted_bytes)

                st.success(f"Backup created: {backup_filename} (encrypted with key_id={key_id})")
                log_action(user_id, role, "create_backup", f"table={table_to_backup}, key_id={key_id}")

        st.markdown("---")
        st.markdown("### 🔹 Restore Backup")

        backup_files = [f for f in os.listdir(backup_folder) if f.endswith(".csv.enc")]
        if not backup_files:
            st.info("No encrypted backup files found.")
        else:
            selected_file = st.selectbox("Select backup file to restore", backup_files)
            if st.button("Restore Selected Backup"):
                import io
                # Extract key_id from filename if available
                try:
                    key_id_in_name = int(selected_file.split("_key")[-1].split(".csv.enc")[0])
                except:
                    key_id_in_name = None

                # Attempt to fetch the correct key from fernet_keys table
                conn = db_connect()
                cur = conn.cursor()
                if key_id_in_name:
                    cur.execute("SELECT key_value FROM fernet_keys WHERE key_id=?", (key_id_in_name,))
                else:
                    cur.execute("SELECT key_value FROM fernet_keys ORDER BY key_id DESC LIMIT 1")
                row = cur.fetchone()
                if not row:
                    st.error("Fernet key for this backup not found! Restore aborted.")
                    conn.close()
                    st.stop()
                fernet = Fernet(row[0].encode())

                file_path = os.path.join(backup_folder, selected_file)
                with open(file_path, "rb") as f:
                    encrypted_bytes = f.read()
                try:
                    decrypted_bytes = fernet.decrypt(encrypted_bytes)
                except Exception as e:
                    st.error(f"Failed to decrypt backup: {e}")
                    conn.close()
                    st.stop()

                df = pd.read_csv(io.BytesIO(decrypted_bytes))

                # Parse table name from filename
                table_name = selected_file.split("_backup_")[0]

                try:
                    # Overwrite existing table data
                    cur.execute(f"DELETE FROM {table_name}")
                    df.to_sql(table_name, conn, if_exists='append', index=False)
                    conn.commit()
                    st.success(f"Backup restored into table '{table_name}' successfully!")
                    log_action(user_id, role, "restore_backup", f"Restored {selected_file} into {table_name}")
                except Exception as e:
                    st.error(f"Failed to restore backup: {e}")
                finally:
                    conn.close()



    # Audit Logs + activity graphs (admin)
    elif choice == "Audit Logs" and role == "admin":
        st.subheader("Audit Logs")
        conn = db_connect()
        df_logs = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn)
        conn.close()
        st.dataframe(df_logs)

        st.markdown("### Activity graph: number of actions per day")
        if not df_logs.empty:
            # prepare daily counts
            df_logs["date"] = pd.to_datetime(df_logs["timestamp"]).dt.date
            counts = df_logs.groupby(["date", "action"]).size().unstack(fill_value=0)
            st.line_chart(counts)
            st.markdown("You can hover to inspect daily counts per action.")
        else:
            st.info("No logs yet to display graph.")

    # Retention Settings
    elif choice == "Retention Settings" and role == "admin":
        st.subheader("Data Retention")
        current_days = get_retention_days()
        days = st.number_input("Retention days (delete patient records older than this)", min_value=1, value=current_days, step=1)
        if st.button("Save retention days"):
            set_retention_days(days)
            st.success(f"Retention days set to {days}")
            log_action(user_id, role, "set_retention", f"days={days}")
        if st.button("Run retention cleanup now"):
            removed = retention_cleanup(days)
            st.success(f"Removed {removed} patient records older than {days} days.")
            log_action(user_id, role, "retention_cleanup", f"removed={removed}, days={days}")

    # Fernet Keys page (admin)
    elif choice == "Fernet Keys" and role == "admin":
        st.subheader("Fernet Key Management (Demo)")
        st.write("A single Fernet key is stored in `fernet.key` in the app folder for demo purposes. In production, store keys in a secure vault.")
        st.code(FERNET_KEY.decode())
        if st.button("Rotate key (demo)"):
            
            new_key = Fernet.generate_key()
            with open(FERNET_KEY_FILE, "wb") as f:
                f.write(new_key)
            st.success("New key generated and written to fernet.key (existing records remain encrypted with old key).")
            log_action(user_id, role, "rotate_fernet_key")

# -------------------------------
# MAIN APP (WITH CONSENT + SESSION STATE)
# -------------------------------
def main():
    st.set_page_config(page_title="Hospital Privacy Dashboard", layout="wide")

    # Auto-refresh every 5 seconds
    st_autorefresh(interval=5000, key="auto_refresh")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.role = None
    if "consent_given" not in st.session_state:
        st.session_state.consent_given = False
    if "last_sync" not in st.session_state:
        st.session_state.last_sync = "Not synced yet"

    # Update system uptime
    if "uptime_placeholder" not in st.session_state:
        st.session_state.uptime_placeholder = st.empty()
    st.session_state.uptime_placeholder.metric("System Uptime", get_system_uptime())

    # Show consent banner BEFORE login is allowed
    consent_ok = show_consent_banner()
    if not consent_ok:
        st.stop()  

    if st.session_state.logged_in:
        dashboard()
    else:
        st.title("🔐 Hospital Privacy & Security Login")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            user = login_user(username, password)

            if user:
                user_id, role = user
                st.session_state.logged_in = True
                st.session_state.user_id = user_id
                st.session_state.role = role
                log_action(user_id, role, "login_success")
                st.session_state.last_sync = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.rerun()
            else:
                st.error("Invalid credentials")
                log_action(0, "unknown", "login_failed")

if __name__ == "__main__":
    main()
