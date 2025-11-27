#!/usr/bin/env python3
# Trading App (LOT + Auto P/L, No External Library)
# Perbaikan: PBKDF2 password hashing, Decimal untuk perhitungan, context manager DB, validasi input, perbaikan CSV/format.

import sqlite3
import hmac
import hmac
import os
import datetime
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from decimal import Decimal, InvalidOperation, getcontext

# Set precision cukup untuk perhitungan trading
getcontext().prec = 28

DB_FILE = "trading_app_lot.db"
PBKDF2_ITER = 150_000

# ===========================
# DATABASE
# ===========================
def get_conn():
    # Tidak menggunakan check_same_thread atau row_factory khusus di sini,
    # cukup kembalikan koneksi baru. Gunakan context manager di fungsi lain.
    return sqlite3.connect(DB_FILE)

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

# Password hashing using PBKDF2 with random salt
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
    # Simpan numeric sebagai string (Decimal str) untuk menjaga presisi
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

# ===========================
# GUI APP
# ===========================
class TradingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Trading App — LOT + Auto Profit/Loss")
        self.geometry("1080x650")
        self.user_id = None
        self.username = None
        self.selected_id = None

        self.build_login()

    # --------------------------
    # LOGIN SCREEN
    # --------------------------
    def build_login(self):
        for w in self.winfo_children(): w.destroy()

        frame = ttk.Frame(self, padding=25)
        frame.pack(expand=True)

        ttk.Label(frame, text="LOGIN", font=("Segoe UI", 16, "bold")).pack(pady=10)

        ttk.Label(frame, text="Username").pack(anchor="w")
        self.e_user = ttk.Entry(frame, width=30)
        self.e_user.pack(pady=4)

        ttk.Label(frame, text="Password").pack(anchor="w")
        self.e_pass = ttk.Entry(frame, show="*", width=30)
        self.e_pass.pack(pady=4)

        btns = ttk.Frame(frame)
        btns.pack(pady=12)

        ttk.Button(btns, text="Login", command=self.do_login).pack(side="left", padx=6)
        ttk.Button(btns, text="Register", command=self.do_register).pack(side="left", padx=6)

    def do_register(self):
        u = self.e_user.get().strip()
        p = self.e_pass.get().strip()
        if not u or not p:
            messagebox.showwarning("Error", "Isi username & password")
            return
        ok, msg = create_user(u, p)
        messagebox.showinfo("Info" if ok else "Gagal", msg)

    def do_login(self):
        u = self.e_user.get().strip()
        p = self.e_pass.get().strip()
        ok, result = authenticate(u, p)

        if ok:
            self.user_id = result
            self.username = u
            self.build_main()
        else:
            messagebox.showerror("Gagal Login", result)

    # --------------------------
    # MAIN SCREEN
    # --------------------------
    def build_main(self):
        for w in self.winfo_children(): w.destroy()

        # TOP BAR
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text=f"User: {self.username}", font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(top, text="Logout", command=self.logout).pack(side="right")
        ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="right", padx=5)

        # FORM INPUT
        form = ttk.LabelFrame(self, text="Input / Edit Catatan Trading", padding=10)
        form.pack(fill="x", padx=10, pady=10)

        # Row 0
        ttk.Label(form, text="Market").grid(row=0, column=0, sticky="w", padx=2, pady=2)
        self.e_market = ttk.Entry(form, width=20); self.e_market.grid(row=0, column=1, padx=2, pady=2)

        ttk.Label(form, text="Open").grid(row=0, column=2, sticky="w", padx=2, pady=2)
        self.e_open = ttk.Entry(form, width=20); self.e_open.grid(row=0, column=3, padx=2, pady=2)

        # Row 1
        ttk.Label(form, text="TP").grid(row=1, column=0, sticky="w", padx=2, pady=2)
        self.e_tp = ttk.Entry(form, width=20); self.e_tp.grid(row=1, column=1, padx=2, pady=2)

        ttk.Label(form, text="SL").grid(row=1, column=2, sticky="w", padx=2, pady=2)
        self.e_sl = ttk.Entry(form, width=20); self.e_sl.grid(row=1, column=3, padx=2, pady=2)

        # Row 2
        ttk.Label(form, text="Lot").grid(row=2, column=0, sticky="w", padx=2, pady=2)
        self.e_lot = ttk.Entry(form, width=20); self.e_lot.grid(row=2, column=1, padx=2, pady=2)

        ttk.Label(form, text="Side").grid(row=2, column=2, sticky="w", padx=2, pady=2)
        # Bungkus radiobutton agar layout konsisten
        rb_frame = ttk.Frame(form)
        rb_frame.grid(row=2, column=3, padx=2, pady=2, sticky="w")
        self.side_var = tk.StringVar(value="BUY")
        ttk.Radiobutton(rb_frame, text="BUY", variable=self.side_var, value="BUY").pack(side="left", padx=4)
        ttk.Radiobutton(rb_frame, text="SELL", variable=self.side_var, value="SELL").pack(side="left", padx=4)

        # Row 3
        ttk.Label(form, text="Keterangan").grid(row=3, column=0, sticky="w", padx=2, pady=2)
        self.e_note = ttk.Entry(form, width=60)
        self.e_note.grid(row=3, column=1, columnspan=3, pady=5, padx=2, sticky="we")

        # BUTTONS
        bf = ttk.Frame(form)
        bf.grid(row=4, column=0, columnspan=4, pady=10)

        ttk.Button(bf, text="Tambah", command=self.add_action).pack(side="left", padx=5)
        ttk.Button(bf, text="Update", command=self.update_action).pack(side="left", padx=5)
        ttk.Button(bf, text="Hapus", command=self.delete_action).pack(side="left", padx=5)
        ttk.Button(bf, text="Clear", command=self.clear_form).pack(side="left", padx=5)

        # TABLE
        cols = ("id","market","open","tp","sl","lot","side","pl","note","ts")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)

        headers = ["ID","Market","Open","TP","SL","Lot","Side","P/L","Note","Timestamp"]
        widths  = [40,120,90,90,90,60,70,100,250,150]

        for c,h,w in zip(cols,headers,widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w)

        self.tree.pack(fill="both", expand=True, padx=10)
        self.tree.bind("<ButtonRelease-1>", self.select_row)

        # FILTER BAR
        bottom = ttk.Frame(self, padding=10)
        bottom.pack(fill="x")

        ttk.Label(bottom, text="Dari (YYYY-MM-DD)").pack(side="left")
        self.f_from = ttk.Entry(bottom, width=12); self.f_from.pack(side="left", padx=4)

        ttk.Label(bottom, text="Sampai").pack(side="left")
        self.f_to = ttk.Entry(bottom, width=12); self.f_to.pack(side="left", padx=4)

        ttk.Button(bottom, text="Filter", command=self.load_table).pack(side="left", padx=4)
        ttk.Button(bottom, text="Clear", command=self.clear_filter).pack(side="left", padx=4)

        self.lbl_total = ttk.Label(bottom, text="Total: 0")
        self.lbl_total.pack(side="right")

        self.load_table()

    # --------------------------
    # FORM ACTIONS
    # --------------------------
    def clear_form(self):
        for e in (self.e_market, self.e_open, self.e_tp, self.e_sl, self.e_lot, self.e_note):
            e.delete(0, "end")
        self.side_var.set("BUY")
        self.selected_id = None

    def add_action(self):
        # Validasi dasar dan parsing menggunakan Decimal
        market = self.e_market.get().strip()
        note = self.e_note.get().strip()
        if not market:
            messagebox.showwarning("Validasi", "Market harus diisi.")
            return

        try:
            open_p = Decimal(self.e_open.get().strip())
            tp = Decimal(self.e_tp.get().strip())
            sl = Decimal(self.e_sl.get().strip())
            lot = Decimal(self.e_lot.get().strip())
        except InvalidOperation:
            messagebox.showerror("Error", "Open/TP/SL/Lot harus angka yang valid.")
            return

        if lot <= 0:
            messagebox.showerror("Error", "Lot harus lebih besar dari 0.")
            return

        side = self.side_var.get()

        # Auto P/L (menggunakan Decimal)
        if side == "BUY":
            pl = (tp - open_p) * lot
        else:
            pl = (open_p - tp) * lot

        try:
            add_note(self.user_id, market, open_p, tp, sl, lot, side, pl, note)
            self.clear_form()
            self.load_table()
            messagebox.showinfo("Sukses", "Catatan berhasil ditambahkan.")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menambahkan catatan: {e}")

    def update_action(self):
        if not self.selected_id:
            messagebox.showwarning("Pilih", "Pilih baris dulu.")
            return

        market = self.e_market.get().strip()
        note = self.e_note.get().strip()
        if not market:
            messagebox.showwarning("Validasi", "Market harus diisi.")
            return

        try:
            open_p = Decimal(self.e_open.get().strip())
            tp = Decimal(self.e_tp.get().strip())
            sl = Decimal(self.e_sl.get().strip())
            lot = Decimal(self.e_lot.get().strip())
        except InvalidOperation:
            messagebox.showerror("Error", "Open/TP/SL/Lot harus angka yang valid.")
            return

        if lot <= 0:
            messagebox.showerror("Error", "Lot harus lebih besar dari 0.")
            return

        side = self.side_var.get()
        if side == "BUY":
            pl = (tp - open_p) * lot
        else:
            pl = (open_p - tp) * lot

        try:
            update_note(self.selected_id, market, open_p, tp, sl, lot, side, pl, note)
            self.clear_form()
            self.load_table()
            messagebox.showinfo("Sukses", "Catatan berhasil diupdate.")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal mengupdate catatan: {e}")

    def delete_action(self):
        if not self.selected_id:
            messagebox.showwarning("Pilih", "Pilih baris dulu.")
            return

        if messagebox.askyesno("Konfirmasi", "Hapus catatan ini?"):
            try:
                delete_note(self.selected_id)
                self.clear_form()
                self.load_table()
            except Exception as e:
                messagebox.showerror("Error", f"Gagal menghapus catatan: {e}")

    # --------------------------
    # TABLE SELECT
    # --------------------------
    def select_row(self, event):
        item = self.tree.selection()
        if not item: return

        vals = self.tree.item(item[0])["values"]
        if not vals:
            return

        self.selected_id = vals[0]

        # Nilai yang didapat dari DB disimpan sebagai string (Decimal str), masukkan langsung ke entry
        self.e_market.delete(0,"end"); self.e_market.insert(0, vals[1] if vals[1] is not None else "")
        self.e_open.delete(0,"end"); self.e_open.insert(0, vals[2] if vals[2] is not None else "")
        self.e_tp.delete(0,"end"); self.e_tp.insert(0, vals[3] if vals[3] is not None else "")
        self.e_sl.delete(0,"end"); self.e_sl.insert(0, vals[4] if vals[4] is not None else "")
        self.e_lot.delete(0,"end"); self.e_lot.insert(0, vals[5] if vals[5] is not None else "")
        self.side_var.set(vals[6] if vals[6] is not None else "BUY")
        self.e_note.delete(0,"end"); self.e_note.insert(0, vals[8] if vals[8] is not None else "")

    # --------------------------
    # FILTER + CSV
    # --------------------------
    def parse_date(self, s):
        if not s:
            return None
        s = s.strip()
        if not s:
            return None
        try:
            datetime.datetime.strptime(s, "%Y-%m-%d")
            return s
        except Exception:
            messagebox.showerror("Format Salah", "Gunakan format YYYY-MM-DD")
            return None

    def load_table(self):
        d1 = self.parse_date(self.f_from.get()) if hasattr(self, "f_from") else None
        d2 = self.parse_date(self.f_to.get()) if hasattr(self, "f_to") else None

        rows = fetch_notes(self.user_id, d1, d2)

        for r in self.tree.get_children():
            self.tree.delete(r)

        total = Decimal("0")
        for row in rows:
            # Row: (id, market, open_price, tp, sl, lot, side, pl, note, timestamp)
            display_row = list(row)
            # Format numeric fields; handle None
            for idx in (2,3,4,5,7):
                val = row[idx]
                if val is None:
                    display_row[idx] = ""
                else:
                    try:
                        dec = Decimal(str(val))
                        if idx == 7:
                            # P/L format with sign and 2 decimals
                            display_row[idx] = f"{dec:.2f}"
                        else:
                            display_row[idx] = f"{dec:.5f}".rstrip('0').rstrip('.') if dec % 1 else f"{dec:.0f}"
                    except Exception:
                        display_row[idx] = str(val)
            # Insert formatted
            self.tree.insert("", "end", values=tuple(display_row))
            # Sum total using original pl value (row[7])
            try:
                total += Decimal(str(row[7])) if row[7] is not None else Decimal("0")
            except Exception:
                # skip if malformed
                pass

        self.lbl_total.config(text=f"Total: {total:,.2f}")

    def clear_filter(self):
        self.f_from.delete(0,"end")
        self.f_to.delete(0,"end")
        self.load_table()

    def export_csv(self):
        rows = fetch_notes(self.user_id)

        if not rows:
            messagebox.showwarning("Kosong", "Tidak ada data.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files","*.csv")]
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ID","Market","Open","TP","SL","Lot","Side","P/L","Note","Timestamp"])
                for row in rows:
                    # Format numeric fields
                    out = list(row)
                    for idx in (2,3,4,5,7):
                        val = row[idx]
                        if val is None or val == "":
                            out[idx] = ""
                        else:
                            try:
                                dec = Decimal(str(val))
                                out[idx] = f"{dec:.5f}" if idx in (2,3,4,5) else f"{dec:.2f}"
                            except Exception:
                                out[idx] = str(val)
                    w.writerow(out)
            messagebox.showinfo("Sukses", f"CSV disimpan di:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyimpan CSV: {e}")

    # --------------------------
    # LOGOUT
    # --------------------------
    def logout(self):
        self.user_id = None
        self.username = None
        self.selected_id = None
        self.build_login()

# ===========================
# RUN APP
# ===========================
def main():
    init_db()
    app = TradingApp()
    app.mainloop()

if __name__ == "__main__":
    main()