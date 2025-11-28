#!/usr/bin/env python3
"""
Streamlit trading app with:
- PBKDF2 password hashing (user table)
- Decimal-based P/L calculation
- pl_per_lot + pl_total stored in DB
- Cached fetch_notes + auto-clear cache on data change
- WebSocket push price streamer (Binance demo) via background thread
- Subscribe/unsubscribe symbols, use live price as Open, compute and save notes

NOTE: This variant adds a safe fallback if the `websocket-client` package
is not installed so the app won't crash with ModuleNotFoundError.
When the websocket client is missing, live price features are disabled
and the UI shows a helpful message. To re-enable live streaming,
install `websocket-client` (see requirements.txt).
"""
import os
import sqlite3
import hashlib
import hmac
import datetime
import io
import csv
import threading
import time
import json
from decimal import Decimal, InvalidOperation, getcontext
from typing import Dict, Optional, Tuple
import streamlit as st
import pandas as pd

# Small compatibility helper for rerun
def try_rerun():
    """Try to rerun the Streamlit script. Some Streamlit versions expose
    experimental_rerun, others expose rerun, and some may not expose either.
    This helper calls the available API and never raises if missing."""
    try:
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
        elif hasattr(st, "rerun"):
            st.rerun()
    except Exception:
        # silently ignore if not available
        return

# Try to import websocket-client, but don't let the app crash if it's missing.
try:
    from websocket import WebSocketApp  # websocket-client package
    HAS_WS = True
except Exception:
    WebSocketApp = None
    HAS_WS = False

# Precision
getcontext().prec = 28

DB_FILE = "trading_app_lot.db"
PBKDF2_ITER = 150_000
BINANCE_WS_BASE = "wss://stream.binance.com:9443/stream?streams="

# -----------------------
# DB helpers & migration
# -----------------------
def get_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def ensure_column_exists(table: str, column: str, col_def: str):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        cols = [r[1] for r in cur.fetchall()]
        if column not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
            conn.commit()

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
                pl_per_lot TEXT,
                pl TEXT,
                note TEXT,
                timestamp TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()
    # Ensure migration column exists
    ensure_column_exists("notes", "pl_per_lot", "TEXT")

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

def add_note(user_id, market, open_p, tp, sl, lot, side, pl_per_lot, pl_total, note):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO notes (user_id, market, open_price, tp, sl, lot, side, pl_per_lot, pl, note, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (user_id, market, str(open_p), str(tp), str(sl), str(lot), side, str(pl_per_lot), str(pl_total), note, ts))
        conn.commit()

def update_note(note_id, market, open_p, tp, sl, lot, side, pl_per_lot, pl_total, note):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE notes
            SET market=?, open_price=?, tp=?, sl=?, lot=?, side=?, pl_per_lot=?, pl=?, note=?
            WHERE id=?
        """, (market, str(open_p), str(tp), str(sl), str(lot), side, str(pl_per_lot), str(pl_total), note, note_id))
        conn.commit()

def delete_note(note_id):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM notes WHERE id=?", (note_id,))
        conn.commit()

def fetch_notes(user_id, d1=None, d2=None):
    with get_conn() as conn:
        cur = conn.cursor()
        q = "SELECT id, market, open_price, tp, sl, lot, side, pl_per_lot, pl, note, timestamp FROM notes WHERE user_id=?"
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
# Caching for fetch_notes
# -----------------------
if hasattr(st, "cache_data"):
    @st.cache_data(ttl=300)
    def cached_fetch_notes(user_id, d1, d2):
        return fetch_notes(user_id, d1, d2)
elif hasattr(st, "experimental_memo"):
    @st.experimental_memo
    def cached_fetch_notes(user_id, d1, d2):
        return fetch_notes(user_id, d1, d2)
elif hasattr(st, "cache"):
    @st.cache
    def cached_fetch_notes(user_id, d1, d2):
        return fetch_notes(user_id, d1, d2)
else:
    def cached_fetch_notes(user_id, d1, d2):
        return fetch_notes(user_id, d1, d2)

def clear_cache():
    cleared = False
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        if hasattr(st, "cache_data"):
            st.cache_data.clear(); cleared = True
    except Exception:
        pass
    try:
        if hasattr(st, "cache_resource"):
            st.cache_resource.clear(); cleared = True
    except Exception:
        pass
    try:
        if hasattr(st, "experimental_memo"):
            st.experimental_memo.clear(); cleared = True
    except Exception:
        pass
    try:
        if hasattr(st, "experimental_singleton"):
            st.experimental_singleton.clear(); cleared = True
    except Exception:
        pass
    st.session_state['last_cache_cleared'] = now if cleared else st.session_state.get('last_cache_cleared', None)
    return cleared

# -----------------------
# Price streamer (WebSocket) - Binance combined trade streams demo
# -----------------------
class PriceStreamer:
    def __init__(self):
        self._lock = threading.Lock()
        self._symbols = set()
        self._prices: Dict[str, Tuple[Decimal, str]] = {}
        self._ws_app: Optional[WebSocketApp] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _build_url(self):
        if not self._symbols:
            return None
        streams = "/".join(f"{s.lower()}@trade" for s in sorted(self._symbols))
        return BINANCE_WS_BASE + streams

    def _on_message(self, ws, message):
        try:
            obj = json.loads(message)
            data = obj.get("data") or obj
            sym = (data.get("s") or "").upper()
            price_s = data.get("p") or data.get("c")
            if not sym or not price_s:
                return
            with self._lock:
                self._prices[sym] = (Decimal(price_s), datetime.datetime.utcnow().isoformat())
        except Exception:
            pass

    def _on_error(self, ws, error):
        print("WS error:", error)

    def _on_close(self, ws, close_status_code, close_msg):
        print("WS closed", close_status_code, close_msg)

    def _on_open(self, ws):
        print("WS opened")

    def _run_ws(self, url):
        # If websocket-client is not installed, do not attempt to run connection.
        if not HAS_WS:
            print("websocket-client not available: skipping WS connection.")
            return

        self._stop_event.clear()
        def _run():
            while not self._stop_event.is_set():
                try:
                    self._ws_app = WebSocketApp(url,
                                               on_message=self._on_message,
                                               on_error=self._on_error,
                                               on_close=self._on_close,
                                               on_open=self._on_open)
                    self._ws_app.run_forever(ping_interval=20, ping_timeout=10)
                except Exception as e:
                    print("WS run exception:", e)
                if not self._stop_event.is_set():
                    time.sleep(2)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self._thread = t

    def _stop_ws(self):
        self._stop_event.set()
        try:
            if self._ws_app:
                self._ws_app.close()
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=1)
        self._ws_app = None
        self._thread = None

    def subscribe(self, symbol: str) -> bool:
        """
        Subscribe to a symbol. Returns True on success, False if live WS is disabled.
        """
        if not HAS_WS:
            # Do not add subscriptions when websocket-client is missing.
            return False
        symbol = symbol.upper()
        with self._lock:
            if symbol in self._symbols:
                return True
            self._symbols.add(symbol)
        self._restart_connection()
        return True

    def unsubscribe(self, symbol: str) -> bool:
        """
        Unsubscribe from a symbol. Returns False if WS lib missing.
        """
        if not HAS_WS:
            return False
        symbol = symbol.upper()
        with self._lock:
            if symbol in self._symbols:
                self._symbols.remove(symbol)
                self._prices.pop(symbol, None)
        self._restart_connection()
        return True

    def get_price(self, symbol: str) -> Optional[Tuple[Decimal, str]]:
        symbol = symbol.upper()
        with self._lock:
            return self._prices.get(symbol)

    def list_symbols(self):
        with self._lock:
            return sorted(self._symbols)

    def _restart_connection(self):
        self._stop_ws()
        url = self._build_url()
        if url:
            self._run_ws(url)

    def stop(self):
        self._stop_ws()

# Use a cached resource for the streamer
if hasattr(st, "cache_resource"):
    @st.cache_resource
    def get_streamer():
        return PriceStreamer()
else:
    def get_streamer():
        return PriceStreamer()

# -----------------------
# Contract mapping (defaults)
# -----------------------
CONTRACT_MAP = {
    "BTCUSDT": Decimal("1"),
    "ETHUSDT": Decimal("1"),
    # Add more instrument-specific contract sizes if needed
}

def get_contract_value_for_symbol(symbol: str) -> Decimal:
    return CONTRACT_MAP.get(symbol.upper(), Decimal("1"))

# -----------------------
# Streamlit UI
# -----------------------
st.set_page_config(page_title="Trading App - Live WS", layout="wide")
init_db()

# session defaults
if 'user_id' not in st.session_state:
    st.session_state['user_id'] = None
if 'username' not in st.session_state:
    st.session_state['username'] = None
if 'auto_clear_cache' not in st.session_state:
    st.session_state['auto_clear_cache'] = True
if 'last_cache_cleared' not in st.session_state:
    st.session_state['last_cache_cleared'] = None

# Sidebar: account + cache + WS control
st.sidebar.title("Akun")
mode = st.sidebar.selectbox("Mode", ["Login", "Register"]) if st.session_state['user_id'] is None else "Logged"

st.sidebar.markdown("### Cache")
st.session_state['auto_clear_cache'] = st.sidebar.checkbox("Auto clear cache on data change", value=st.session_state['auto_clear_cache'])
if st.sidebar.button("Clear cache now"):
    ok = clear_cache()
    if ok:
        st.sidebar.success("Cache dibersihkan.")
    else:
        st.sidebar.info("Tidak ada cache yang dibersihkan atau API tidak tersedia.")
if st.session_state['last_cache_cleared']:
    st.sidebar.caption(f"Last cleared: {st.session_state['last_cache_cleared']}")

# WebSocket controls
st.sidebar.markdown("### Live Price (WebSocket)")
if not HAS_WS:
    st.sidebar.warning("Package 'websocket-client' tidak terpasang. Fitur live price dinonaktifkan. "
                       "Tambahkan 'websocket-client' ke requirements.txt dan redeploy untuk mengaktifkan.")
streamer = get_streamer()
ws_sym = st.sidebar.text_input("Symbol (e.g. BTCUSDT)", value="BTCUSDT")
col_a, col_b = st.sidebar.columns(2)
with col_a:
    if st.sidebar.button("Subscribe"):
        ok = streamer.subscribe(ws_sym.strip().upper())
        if not ok:
            st.sidebar.error("Tidak dapat subscribe: paket websocket-client tidak tersedia.")
        else:
            try_rerun()
with col_b:
    if st.sidebar.button("Unsubscribe"):
        ok = streamer.unsubscribe(ws_sym.strip().upper())
        if not ok:
            st.sidebar.error("Tidak dapat unsubscribe: paket websocket-client tidak tersedia.")
        else:
            try_rerun()
if st.sidebar.button("Stop streamer"):
    streamer.stop()
active = streamer.list_symbols()
if active:
    st.sidebar.write("Active subs:")
    for s in active:
        p = streamer.get_price(s)
        st.sidebar.write(f"- {s}: {p[0]:,.8f} (ts {p[1]})" if p else f"- {s}: no price yet")
else:
    st.sidebar.write("No active subscriptions")

# Auth UI
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
                if st.session_state['auto_clear_cache']:
                    clear_cache()
                try_rerun()
            else:
                st.sidebar.error(res)
else:
    st.sidebar.success(f"Login: {st.session_state['username']}")
    if st.sidebar.button("Logout"):
        st.session_state['user_id'] = None
        st.session_state['username'] = None
        if st.session_state['auto_clear_cache']:
            clear_cache()
        try_rerun()

if st.session_state['user_id'] is None:
    st.info("Silakan login atau registrasi di sidebar.")
    st.stop()

# Main application UI
st.title("Trading App — LOT + Auto P/L (Streamlit + WebSocket)")
st.write(f"User: {st.session_state['username']}")

col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Tambah / Edit Catatan")
    notes_for_user = cached_fetch_notes(st.session_state['user_id'], None, None)
    note_ids = [str(r[0]) for r in notes_for_user]
    edit_choice = st.selectbox("Pilih ID untuk edit/hapus (kosong = tambah)", [""] + note_ids)
    if edit_choice:
        selected = next((r for r in notes_for_user if str(r[0]) == edit_choice), None)
        if selected:
            pre_market = selected[1] or ""
            pre_open = selected[2] or ""
            pre_tp = selected[3] or ""
            pre_sl = selected[4] or ""
            pre_lot = selected[5] or ""
            pre_side = selected[6] or "BUY"
            pre_pl_per_lot = selected[7] or ""
            pre_note = selected[9] or ""
        else:
            pre_market = pre_open = pre_tp = pre_sl = pre_lot = pre_side = pre_pl_per_lot = pre_note = ""
    else:
        pre_market = pre_open = pre_tp = pre_sl = pre_lot = pre_pl_per_lot = pre_note = ""
        pre_side = "BUY"

    market = st.text_input("Market", value=str(pre_market))
    open_p_str = st.text_input("Open", value=str(pre_open))
    tp_str = st.text_input("TP", value=str(pre_tp))
    sl_str = st.text_input("SL", value=str(pre_sl))
    lot_str = st.text_input("Lot", value=str(pre_lot))
    side = st.selectbox("Side", ["BUY", "SELL"], index=0 if pre_side == "BUY" else 1)
    # value per point per lot: default from contract map
    default_vpl = get_contract_value_for_symbol(market if market else ws_sym)
    vpl_str = st.text_input("Value per point per lot (currency per price unit)", value=str(pre_pl_per_lot if pre_pl_per_lot != "" else str(default_vpl)))
    note_text = st.text_input("Keterangan", value=str(pre_note))

    # Buttons
    btn_col1, btn_col2, btn_col3 = st.columns(3)
    with btn_col1:
        if st.button("Gunakan harga live sebagai Open"):
            # try get last live price for market or ws_sym
            sym_to_check = market.strip().upper() or ws_sym.strip().upper()
            p = streamer.get_price(sym_to_check)
            if p:
                st.session_state['open_from_live'] = str(p[0])
                st.success(f"Open diset dari live price {sym_to_check}: {p[0]:,.8f}")
            else:
                st.warning("Tidak ada live price untuk simbol tersebut. Pastikan sudah subscribe.")

    with btn_col1:
        if st.button("Simpan / Tambah"):
            market_val = market.strip()
            if not market_val:
                st.error("Market harus diisi.")
            else:
                try:
                    open_p = Decimal(open_p_str.strip() or st.session_state.get('open_from_live', '').strip())
                    tp = Decimal(tp_str.strip())
                    sl = Decimal(sl_str.strip())
                    lot = Decimal(lot_str.strip())
                    value_per_lot = Decimal(vpl_str.strip())
                except (InvalidOperation, ValueError):
                    st.error("Open/TP/SL/Lot/Value per lot harus angka yang valid.")
                else:
                    if lot <= 0:
                        st.error("Lot harus > 0.")
                    else:
                        price_diff = (tp - open_p) if side == "BUY" else (open_p - tp)
                        pl_per_lot = price_diff * value_per_lot
                        pl_total = pl_per_lot * lot
                        try:
                            if edit_choice:
                                update_note(int(edit_choice), market_val, open_p, tp, sl, lot, side, pl_per_lot, pl_total, note_text.strip())
                                st.success("Catatan diupdate.")
                            else:
                                add_note(st.session_state['user_id'], market_val, open_p, tp, sl, lot, side, pl_per_lot, pl_total, note_text.strip())
                                st.success("Catatan ditambahkan.")
                            if st.session_state['auto_clear_cache']:
                                clear_cache()
                            try_rerun()
                        except Exception as e:
                            st.error(f"Gagal menyimpan: {e}")

    with btn_col2:
        if st.button("Hapus"):
            if not edit_choice:
                st.warning("Pilih ID untuk menghapus.")
            else:
                delete_note(int(edit_choice))
                st.success("Catatan dihapus.")
                if st.session_state['auto_clear_cache']:
                    clear_cache()
                try_rerun()

    with btn_col3:
        if st.button("Bersihkan Form"):
            st.session_state.pop('open_from_live', None)
            try_rerun()

with col2:
    st.subheader("Daftar Catatan & Live Preview")
    c1, c2, c3 = st.columns([1,1,2])
    with c1:
        from_date = st.date_input("Dari (opsional)", value=None)
    with c2:
        to_date = st.date_input("Sampai (opsional)", value=None)
    d1 = from_date.isoformat() if isinstance(from_date, datetime.date) else None
    d2 = to_date.isoformat() if isinstance(to_date, datetime.date) else None
    if d1 == datetime.date.today().isoformat() and d2 == datetime.date.today().isoformat():
        d1 = d2 = None

    rows = cached_fetch_notes(st.session_state['user_id'], d1, d2)
    df = pd.DataFrame(rows, columns=["ID","Market","Open","TP","SL","Lot","Side","P/L per lot","Total P/L","Note","Timestamp"])
    if not df.empty:
        def safe_dec(x):
            try:
                return Decimal(str(x))
            except Exception:
                return x
        # format columns
        for col_name in ["Open","TP","SL"]:
            df[col_name] = df[col_name].apply(lambda v: f"{safe_dec(v):,.5f}" if v not in (None,"") and isinstance(safe_dec(v), Decimal) else (v or ""))
        df["Lot"] = df["Lot"].apply(lambda v: f"{safe_dec(v):,.2f}" if v not in (None,"") and isinstance(safe_dec(v), Decimal) else (v or ""))
        df["P/L per lot"] = df["P/L per lot"].apply(lambda v: f"{safe_dec(v):,.2f}" if v not in (None,"") and isinstance(safe_dec(v), Decimal) else (v or ""))
        df["Total P/L"] = df["Total P/L"].apply(lambda v: f"{safe_dec(v):,.2f}" if v not in (None,"") and isinstance(safe_dec(v), Decimal) else (v or ""))
        st.dataframe(df, use_container_width=True)

        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        st.download_button("Download CSV", data=csv_buf.getvalue().encode("utf-8"), file_name="notes.csv", mime="text/csv")

        try:
            total_sum = sum(Decimal(str(r[8])) for r in rows if r[8] not in (None,""))
            st.metric("Total Semua (Total P/L)", f"{total_sum:,.2f}")
        except Exception:
            pass
    else:
        st.info("Belum ada catatan.")

st.markdown("---")
st.caption("Catatan: WebSocket demo menggunakan Binance. Untuk produksi, sesuaikan provider, autentikasi, dan gunakan DB server untuk concurrency.")