import streamlit as st
import sqlite3
import hashlib, os, hmac
import datetime
import pandas as pd
import matplotlib.pyplot as plt
from decimal import Decimal, InvalidOperation, getcontext
from websocket import WebSocketApp
import threading, time, json, io

# Decimal precision
getcontext().prec = 28

DB_FILE = "trading_app.db"
PBKDF2_ITER = 150000
BINANCE_WS_BASE = "wss://stream.binance.com:9443/stream?streams="

# -------------------------
# DATABASE SETUP
# -------------------------
def get_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                pw TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                market TEXT,
                open_price TEXT,
                tp TEXT,
                sl TEXT,
                lot TEXT,
                side TEXT,
                vpl TEXT,
                pl_total TEXT,
                note TEXT,
                ts TEXT
            )
        """)
        conn.commit()

# -------------------------
# PASSWORD HASH
# -------------------------
def hash_pw(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER)
    return f"{salt.hex()}:{dk.hex()}:{PBKDF2_ITER}"

def verify_pw(password, stored):
    try:
        salt_hex, dk_hex, it = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        dk = bytes.fromhex(dk_hex)
        new_dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(it))
        return hmac.compare_digest(dk, new_dk)
    except:
        return False

# -------------------------
# USER AUTH
# -------------------------
def create_user(username, pw):
    try:
        with get_conn() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (username,pw) VALUES (?,?)",
                      (username, hash_pw(pw)))
            conn.commit()
        return True, "Registrasi berhasil."
    except sqlite3.IntegrityError:
        return False, "Username sudah dipakai."

def authenticate(username, pw):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id,pw FROM users WHERE username=?", (username,))
        row = c.fetchone()
    if not row:
        return False, "User tidak ditemukan."
    uid, stored = row
    return (True, uid) if verify_pw(pw, stored) else (False, "Password salah")

# -------------------------
# NOTES CRUD
# -------------------------
def add_note(uid, market, op, tp, sl, lot, side, vpl, pl_total, note):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO notes (user_id,market,open_price,tp,sl,lot,side,vpl,pl_total,note,ts)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (uid,market,str(op),str(tp),str(sl),str(lot),side,str(vpl),str(pl_total),note,ts))
        conn.commit()

def update_note(nid, market, op, tp, sl, lot, side, vpl, pl_total, note):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
        UPDATE notes SET market=?,open_price=?,tp=?,sl=?,lot=?,side=?,vpl=?,pl_total=?,note=? 
        WHERE id=?
        """, (market,str(op),str(tp),str(sl),str(lot),side,str(vpl),str(pl_total),note,nid))
        conn.commit()

def delete_note(nid):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM notes WHERE id=?", (nid,))
        conn.commit()

def fetch_notes(uid):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id,market,open_price,tp,sl,lot,side,vpl,pl_total,note,ts
            FROM notes WHERE user_id=? ORDER BY ts
        """, (uid,))
        return c.fetchall()

# -------------------------
# WEBSOCKET STREAMER
# -------------------------
class PriceStreamer:
    def __init__(self):
        self._lock = threading.Lock()
        self.symbols = set()
        self.prices = {}
        self.ws = None
        self.thread = None
        self.stop_event = threading.Event()

    def _build_url(self):
        if not self.symbols:
            return None
        stream = "/".join(f"{s.lower()}@trade" for s in self.symbols)
        return BINANCE_WS_BASE + stream

    def _on_msg(self, ws, msg):
        try:
            d = json.loads(msg)
            data = d.get("data")
            if not data:
                return
            sym = data.get("s")
            px = data.get("p") or data.get("c")
            if not sym or not px:
                return
            with self._lock:
                self.prices[sym] = Decimal(px)
        except:
            pass

    def _run(self, url):
        def loop():
            while not self.stop_event.is_set():
                try:
                    self.ws = WebSocketApp(
                        url,
                        on_message=self._on_msg,
                    )
                    self.ws.run_forever()
                except:
                    pass
                time.sleep(2)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        self.thread = t

    def subscribe(self, symbol):
        symbol = symbol.upper()
        with self._lock:
            self.symbols.add(symbol)
        self.restart()

    def unsubscribe(self, symbol):
        symbol = symbol.upper()
        with self._lock:
            if symbol in self.symbols:
                self.symbols.remove(symbol)
        self.restart()

    def get_price(self, symbol):
        return self.prices.get(symbol.upper())

    def restart(self):
        self.stop()
        url = self._build_url()
        if url:
            self.stop_event.clear()
            self._run(url)

    def stop(self):
        self.stop_event.set()
        try:
            if self.ws: self.ws.close()
        except:
            pass

@st.cache_resource
def get_streamer():
    return PriceStreamer()

# -------------------------
# STREAMLIT UI
# -------------------------
st.set_page_config(page_title="Trading App Mobile", layout="wide")
init_db()

# Session
if "uid" not in st.session_state:
    st.session_state.uid = None
if "username" not in st.session_state:
    st.session_state.username = None

# CSS mobile
st.markdown("""
<style>
input, select, textarea {
    font-size: 18px !important;
}
button {
    font-size: 18px !important;
}
section[data-testid="stSidebar"]{display:none;}
</style>
""", unsafe_allow_html=True)

st.title("Trading App (Mobile Version)")
st.caption("Market dropdown + tanpa value otomatis")

# -------------------------
# LOGIN UI
# -------------------------
if st.session_state.uid is None:
    mode = st.selectbox("Mode", ["Login", "Register"])
    username = st.text_input("Username")
    pw = st.text_input("Password", type="password")

    if mode == "Register":
        if st.button("Daftar"):
            ok, msg = create_user(username, pw)
            st.info(msg)
    else:
        if st.button("Login"):
            ok, res = authenticate(username, pw)
            if ok:
                st.session_state.uid = res
                st.session_state.username = username
                st.success("Login berhasil!")
                st.rerun()
            else:
                st.error(res)

    st.stop()

st.success(f"Logged in sebagai: {st.session_state.username}")
if st.button("Logout"):
    st.session_state.uid = None
    st.rerun()

# -------------------------
# MAIN FORM
# -------------------------
st.header("Tambah / Edit Catatan")

notes = fetch_notes(st.session_state.uid)
note_ids = [str(r[0]) for r in notes]
choice = st.selectbox("Edit Catatan", [""] + note_ids)

if choice:
    data = next(r for r in notes if str(r[0]) == choice)
else:
    data = [None,"","","","","","","","","",""]

_, pre_market, pre_open, pre_tp, pre_sl, pre_lot, pre_side, pre_vpl, _, pre_note, _ = data

market = st.selectbox("Market", ["XAUUSD","BTCUSD","USTEC","EURUSD","USDJPY"],
                      index=(["XAUUSD","BTCUSD","USTEC","EURUSD","USDJPY"].index(pre_market)
                             if pre_market in ["XAUUSD","BTCUSD","USTEC","EURUSD","USDJPY"] else 0))

open_str = st.text_input("Open", value=pre_open)
tp_str = st.text_input("TP", value=pre_tp)
sl_str = st.text_input("SL", value=pre_sl)
lot_str = st.text_input("Lot", value=pre_lot)
side = st.selectbox("Side", ["BUY","SELL"], index=0 if pre_side=="BUY" else 1)
vpl_str = st.text_input("Value Per Point Per Lot", value=pre_vpl)
note = st.text_input("Catatan", value=pre_note)

streamer = get_streamer()
if st.button("Gunakan harga live sebagai Open"):
    price = streamer.get_price(market)
    if price:
        open_str = str(price)
        st.info(f"Open diambil dari live price: {price}")
    else:
        st.warning("Harga live tidak tersedia. Pastikan sudah subscribe.")


# -------------------------
# SUBSCRIBE AREA
# -------------------------
st.subheader("Live Price Stream")
sub_sym = st.text_input("Symbol (contoh: BTCUSDT)", value="BTCUSDT")

c1, c2 = st.columns(2)
with c1:
    if st.button("Subscribe"):
        streamer.subscribe(sub_sym)
with c2:
    if st.button("Unsubscribe"):
        streamer.unsubscribe(sub_sym)

price_now = streamer.get_price(sub_sym)
if price_now:
    st.metric(f"{sub_sym}", f"{price_now:,.4f}")


# -------------------------
# SAVE / UPDATE
# -------------------------
if st.button("Simpan"):
    try:
        op = Decimal(open_str)
        tp = Decimal(tp_str)
        sl = Decimal(sl_str)
        lot = Decimal(lot_str)
        vpl = Decimal(vpl_str)
    except:
        st.error("Open/TP/SL/Lot/VPL harus angka.")
        st.stop()

    if lot <= 0:
        st.error("Lot harus > 0")
        st.stop()

    diff = tp - op if side=="BUY" else op - tp
    pl_total = diff * vpl * lot

    if choice:
        update_note(int(choice), market, op, tp, sl, lot, side, vpl, pl_total, note)
        st.success("Catatan diupdate!")
    else:
        add_note(st.session_state.uid, market, op, tp, sl, lot, side, vpl, pl_total, note)
        st.success("Catatan ditambahkan!")

    st.rerun()

if choice and st.button("Hapus"):
    delete_note(int(choice))
    st.success("Catatan dihapus!")
    st.rerun()

# -------------------------
# DISPLAY TABLE
# -------------------------
st.header("Catatan Anda")
notes = fetch_notes(st.session_state.uid)
df = pd.DataFrame(notes, columns=[
    "ID","Market","Open","TP","SL","Lot","Side","VPL","P/L","Catatan","Waktu"
])

if df.empty:
    st.info("Belum ada catatan.")
    st.stop()

st.dataframe(df, use_container_width=True)

# -------------------------
# DOWNLOAD CSV
# -------------------------
buf = io.StringIO()
df.to_csv(buf, index=False)
st.download_button("Download CSV", buf.getvalue(), "notes.csv")

# -------------------------
# GRAPH
# -------------------------
st.header("Grafik P/L")
try:
    df_plot = df.copy()
    df_plot["P/L"] = df_plot["P/L"].astype(float)

    fig1, ax1 = plt.subplots()
    ax1.plot(df_plot["Waktu"], df_plot["P/L"], marker="o")
    ax1.set_title("P/L per Trade")
    ax1.tick_params(axis="x", rotation=45)
    st.pyplot(fig1)

    df_plot["Equity"] = df_plot["P/L"].cumsum()
    fig2, ax2 = plt.subplots()
    ax2.plot(df_plot["Waktu"], df_plot["Equity"], marker="o")
    ax2.set_title("Equity Curve")
    ax2.tick_params(axis="x", rotation=45)
    st.pyplot(fig2)

except Exception as e:
    st.warning(f"Gagal membuat grafik: {e}")
