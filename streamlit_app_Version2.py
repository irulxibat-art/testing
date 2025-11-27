#!/usr/bin/env python3
"""
Simple Streamlit port of trading_app.py (fixed safe rerun + date_input fallback)
- uses same SQLite DB file (trading_app_lot.db)
- PBKDF2 password hashing (compatible with previous example)
- Decimal for financial calculations
- Basic login/register, add/update/delete notes, filter by date, CSV download
"""
import sqlite3
import hashlib
import hmac
import os
import datetime
import io
import csv
from decimal import Decimal, InvalidOperation, getcontext

import streamlit as st
import pandas as pd

getcontext().prec = 28

DB_FILE = "trading_app_lot.db"
PBKDF2_ITER = 150_000

# -----------------------
# Database helpers
# -----------------------
def get_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                market TEXT,
                open_price TEXT,
                tp TEXT,
                sl TEXT,
                lot TEXT,
                side TEXT,
                pl TEXT,
                note TEXT,
                timestamp TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

# -----------------------
# Password hashing (PBKDF2)
# -----------------------
def hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, PBKDF2_ITER)
    return f"{salt.hex()}:{dk.hex()}:{PBKDF2_ITER}"

def verify_pw(pw: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex, iter_str = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        dk = bytes.fromhex(dk_hex)
        iters = int(iter_str)
        new_dk = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, iters)
        return hmac.compare_digest(new_dk, dk)
    except Exception:
        return False

# -----------------------
# CRUD functions
# -----------------------
def create_user(username, password):
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username,password_hash) VALUES (?,?)",
                (username, hash_pw(password))
            )
            conn.commit()
            return True, "Registrasi berhasil."
        except sqlite3.IntegrityError:
            return False, "Username sudah digunakan."
        except Exception as e:
            return False, f"Error: {e}"

def authenticate(username, password):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
    if not row:
        return False, "User tidak ditemukan."
    uid, stored_hash = row
    return (True, uid) if verify_pw(password, stored_hash) else (False, "Password salah.")

def add_note(user_id, market, open_p, tp, sl, lot, side, pl, note):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO notes (user_id, market, open_price, tp, sl, lot, side, pl, note, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (user_id, market, str(open_p), str(tp), str(sl), str(lot), side, str(pl), note, ts))
        conn.commit()

def update_note(note_id, market, open_p, tp, sl, lot, side, pl, note):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE notes
            SET market=?, open_price=?, tp=?, sl=?, lot=?, side=?, pl=?, note=?
            WHERE id=?
        """, (market, str(open_p), str(tp), str(sl), str(lot), side, str(pl), note, note_id))
        conn.commit()

def delete_note(note_id):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM notes WHERE id=?", (note_id,))
        conn.commit()

def fetch_notes(user_id, d1=None, d2=None):
    with get_conn() as conn:
        cur = conn.cursor()
        q = "SELECT id, market, open_price, tp, sl, lot, side, pl, note, timestamp FROM notes WHERE user_id=?"
        params = [user_id]
        if d1:
            q += " AND date(timestamp)>=date(?)"
            params.append(d1)
        if d2:
            q += " AND date(timestamp)<=date(?)"
            params.append(d2)
        q += " ORDER BY timestamp ASC"
        cur.execute(q, tuple(params))
        rows = cur.fetchall()
    return rows

# -----------------------
# Helper: safe rerun (handles environments lacking experimental_rerun)
# -----------------------
def safe_rerun():
    # Best-effort rerun. If experimental_rerun is not available / raises, fallback to st.stop()
    try:
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
            return
    except Exception:
        # ignore and fallback
        pass
    # Fallback: stop execution (user can refresh or interact)
    try:
        st.stop()
    except Exception:
        # last resort: no-op
        return

# -----------------------
# Streamlit app UI
# -----------------------
st.set_page_config(page_title="Trading App", layout="wide")
init_db()

if 'user_id' not in st.session_state:
    st.session_state['user_id'] = None
if 'username' not in st.session_state:
    st.session_state['username'] = None

st.sidebar.title("Akun")
mode = st.sidebar.selectbox("Mode", ["Login", "Register"]) if st.session_state['user_id'] is None else "Logged"
if st.session_state['user_id'] is None:
    username_in = st.sidebar.text_input("Username")
    password_in = st.sidebar.text_input("Password", type="password")
    if mode == "Register":
        if st.sidebar.button("Register"):
            ok, msg = create_user(username_in.strip(), password_in.strip())
            st.sidebar.info(msg)
    else:
        if st.sidebar.button("Login"):
            ok, res = authenticate(username_in.strip(), password_in.strip())
            if ok:
                st.session_state['user_id'] = res
                st.session_state['username'] = username_in.strip()
                # safe rerun instead of direct experimental_rerun
                safe_rerun()
            else:
                st.sidebar.error(res)
else:
    st.sidebar.success(f"Login: {st.session_state['username']}")
    if st.sidebar.button("Logout"):
        st.session_state['user_id'] = None
        st.session_state['username'] = None
        safe_rerun()

if st.session_state['user_id'] is None:
    st.info("Silakan login atau registrasi di sidebar.")
    st.stop()

# Main app for logged user
st.title("Trading App — LOT + Auto P/L (Streamlit)")
st.write(f"User: {st.session_state['username']}")

col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Tambah / Edit Catatan")
    # For edit, user can select existing note id
    notes_for_user = fetch_notes(st.session_state['user_id'])
    note_ids = [str(r[0]) for r in notes_for_user]
    edit_choice = st.selectbox("Pilih ID untuk edit/hapus (kosong = tambah)", [""] + note_ids)
    if edit_choice:
        selected = next((r for r in notes_for_user if str(r[0]) == edit_choice), None)
        if selected:
            # selected: (id, market, open_price, tp, sl, lot, side, pl, note, timestamp)
            pre_market = selected[1] or ""
            pre_open = selected[2] or ""
            pre_tp = selected[3] or ""
            pre_sl = selected[4] or ""
            pre_lot = selected[5] or ""
            pre_side = selected[6] or "BUY"
            pre_note = selected[8] or ""
        else:
            pre_market = pre_open = pre_tp = pre_sl = pre_lot = pre_side = pre_note = ""
    else:
        pre_market = pre_open = pre_tp = pre_sl = pre_lot = pre_note = ""
        pre_side = "BUY"

    market = st.text_input("Market", value=str(pre_market))
    open_p_str = st.text_input("Open", value=str(pre_open))
    tp_str = st.text_input("TP", value=str(pre_tp))
    sl_str = st.text_input("SL", value=str(pre_sl))
    lot_str = st.text_input("Lot", value=str(pre_lot))
    side = st.selectbox("Side", ["BUY", "SELL"], index=0 if pre_side == "BUY" else 1)
    note_text = st.text_input("Keterangan", value=str(pre_note))

    btn_col1, btn_col2, btn_col3 = st.columns(3)
    with btn_col1:
        if st.button("Simpan / Tambah"):
            # Validasi dan parsing Decimal
            try:
                open_p = Decimal(open_p_str.strip())
                tp = Decimal(tp_str.strip())
                sl = Decimal(sl_str.strip())
                lot = Decimal(lot_str.strip())
            except (InvalidOperation, ValueError):
                st.error("Open/TP/SL/Lot harus angka yang valid.")
            else:
                if lot <= 0:
                    st.error("Lot harus > 0.")
                else:
                    pl = (tp - open_p) * lot if side == "BUY" else (open_p - tp) * lot
                    try:
                        if edit_choice:
                            update_note(int(edit_choice), market.strip(), open_p, tp, sl, lot, side, pl, note_text.strip())
                            st.success("Catatan diupdate.")
                        else:
                            add_note(st.session_state['user_id'], market.strip(), open_p, tp, sl, lot, side, pl, note_text.strip())
                            st.success("Catatan ditambahkan.")
                        safe_rerun()
                    except Exception as e:
                        st.error(f"Gagal menyimpan: {e}")

    with btn_col2:
        if st.button("Hapus"):
            if not edit_choice:
                st.warning("Pilih ID untuk menghapus.")
            else:
                delete_note(int(edit_choice))
                st.success("Catatan dihapus.")
                safe_rerun()

    with btn_col3:
        if st.button("Bersihkan Form"):
            safe_rerun()

with col2:
    st.subheader("Daftar Catatan")
    # filter by date
    c1, c2, c3 = st.columns([1,1,2])
    # Some streamlit versions don't accept value=None for date_input -- handle safely
    try:
        from_date = st.date_input("Dari (opsional)", value=None)
    except Exception:
        # fallback to text input for older streamlit versions
        from_date = None
        from_date_text = st.text_input("Dari (YYYY-MM-DD) (opsional)", value="")
        if from_date_text.strip():
            try:
                from_date = datetime.date.fromisoformat(from_date_text.strip())
            except Exception:
                st.error("Format tanggal salah pada field Dari.")

    try:
        to_date = st.date_input("Sampai (opsional)", value=None)
    except Exception:
        to_date = None
        to_date_text = st.text_input("Sampai (YYYY-MM-DD) (opsional)", value="")
        if to_date_text.strip():
            try:
                to_date = datetime.date.fromisoformat(to_date_text.strip())
            except Exception:
                st.error("Format tanggal salah pada field Sampai.")

    # Convert to strings or None
    d1 = from_date.isoformat() if isinstance(from_date, datetime.date) else None
    d2 = to_date.isoformat() if isinstance(to_date, datetime.date) else None
    # If both defaulted to today's date in some streamlit versions, treat as None
    try:
        today_iso = datetime.date.today().isoformat()
        if d1 == today_iso and d2 == today_iso:
            d1 = d2 = None
    except Exception:
        pass

    rows = fetch_notes(st.session_state['user_id'], d1, d2)
    df = pd.DataFrame(rows, columns=["ID","Market","Open","TP","SL","Lot","Side","P/L","Note","Timestamp"])
    if not df.empty:
        # Try convert numeric fields for nicer display
        def safe_dec(x):
            try:
                return Decimal(str(x))
            except Exception:
                return x
        for col in ["Open","TP","SL","Lot","P/L"]:
            df[col] = df[col].apply(lambda v: (f"{safe_dec(v):,.5f}" if col != "P/L" else (f"{safe_dec(v):,.2f}" if isinstance(safe_dec(v), Decimal) else v)) if v not in (None, "") else "")
        st.dataframe(df, use_container_width=True)
        # CSV download
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        st.download_button("Download CSV", data=csv_buf.getvalue().encode("utf-8"), file_name="notes.csv", mime="text/csv")
    else:
        st.info("Belum ada catatan.")

st.markdown("---")
st.caption("Catatan: aplikasi sederhana. Untuk production gunakan DB server (Postgres) dan HTTPS.")