#!/usr/bin/env python3
# Trading App (LOT + Auto P/L, No External Library)

import sqlite3
import hashlib
import datetime
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

DB_FILE = "trading_app_lot.db"

# ===========================
# DATABASE
# ===========================
def get_conn():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_conn()
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
            open_price REAL,
            tp REAL,
            sl REAL,
            lot REAL,
            side TEXT,
            pl REAL,
            note TEXT,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def create_user(username, password):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username,password_hash) VALUES (?,?)",
                    (username, hash_pw(password)))
        conn.commit()
        return True, "Registrasi berhasil."
    except sqlite3.IntegrityError:
        return False, "Username sudah digunakan."
    finally:
        conn.close()

def authenticate(username, password):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username=?",(username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, "User tidak ditemukan."
    uid, hashed = row
    return (True, uid) if hashed == hash_pw(password) else (False, "Password salah.")

def add_note(user_id, market, open_p, tp, sl, lot, side, pl, note):
    conn = get_conn()
    cur = conn.cursor()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT INTO notes (user_id, market, open_price, tp, sl, lot, side, pl, note, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (user_id, market, open_p, tp, sl, lot, side, pl, note, ts))

    conn.commit()
    conn.close()

def update_note(note_id, market, open_p, tp, sl, lot, side, pl, note):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE notes
        SET market=?, open_price=?, tp=?, sl=?, lot=?, side=?, pl=?, note=?
        WHERE id=?
    """, (market, open_p, tp, sl, lot, side, pl, note, note_id))
    conn.commit()
    conn.close()

def delete_note(note_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM notes WHERE id=?", (note_id,))
    conn.commit()
    conn.close()

def fetch_notes(user_id, d1=None, d2=None):
    conn = get_conn()
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
    conn.close()
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
        ttk.Label(form, text="Market").grid(row=0, column=0)
        self.e_market = ttk.Entry(form, width=20); self.e_market.grid(row=0, column=1)

        ttk.Label(form, text="Open").grid(row=0, column=2)
        self.e_open = ttk.Entry(form, width=20); self.e_open.grid(row=0, column=3)

        # Row 1
        ttk.Label(form, text="TP").grid(row=1, column=0)
        self.e_tp = ttk.Entry(form, width=20); self.e_tp.grid(row=1, column=1)

        ttk.Label(form, text="SL").grid(row=1, column=2)
        self.e_sl = ttk.Entry(form, width=20); self.e_sl.grid(row=1, column=3)

        # Row 2
        ttk.Label(form, text="Lot").grid(row=2, column=0)
        self.e_lot = ttk.Entry(form, width=20); self.e_lot.grid(row=2, column=1)

        ttk.Label(form, text="Side").grid(row=2, column=2)
        self.side_var = tk.StringVar(value="BUY")
        ttk.Radiobutton(form, text="BUY", variable=self.side_var, value="BUY").grid(row=2, column=3, sticky="w")
        ttk.Radiobutton(form, text="SELL", variable=self.side_var, value="SELL").grid(row=2, column=3, sticky="e")

        # Row 3
        ttk.Label(form, text="Keterangan").grid(row=3, column=0)
        self.e_note = ttk.Entry(form, width=60)
        self.e_note.grid(row=3, column=1, columnspan=3, pady=5)

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
        if hasattr(self, "selected_id"):
            delattr(self, "selected_id")

    def add_action(self):
        try:
            market = self.e_market.get().strip()
            open_p = float(self.e_open.get())
            tp = float(self.e_tp.get())
            sl = float(self.e_sl.get())
            lot = float(self.e_lot.get())
            side = self.side_var.get()
            note = self.e_note.get().strip()

            # Auto P/L
            pl = (tp - open_p) * lot if side == "BUY" else (open_p - tp) * lot

            add_note(self.user_id, market, open_p, tp, sl, lot, side, pl, note)

            self.clear_form()
            self.load_table()
            messagebox.showinfo("Sukses", "Catatan berhasil ditambahkan.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_action(self):
        if not hasattr(self, "selected_id"):
            messagebox.showwarning("Pilih", "Pilih baris dulu.")
            return

        try:
            market = self.e_market.get().strip()
            open_p = float(self.e_open.get())
            tp = float(self.e_tp.get())
            sl = float(self.e_sl.get())
            lot = float(self.e_lot.get())
            side = self.side_var.get()
            note = self.e_note.get().strip()

            pl = (tp - open_p) * lot if side == "BUY" else (open_p - tp) * lot

            update_note(self.selected_id, market, open_p, tp, sl, lot, side, pl, note)

            self.clear_form()
            self.load_table()
            messagebox.showinfo("Sukses", "Catatan berhasil diupdate.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_action(self):
        if not hasattr(self, "selected_id"):
            messagebox.showwarning("Pilih", "Pilih baris dulu.")
            return

        if messagebox.askyesno("Konfirmasi", "Hapus catatan ini?"):
            delete_note(self.selected_id)
            self.clear_form()
            self.load_table()

    # --------------------------
    # TABLE SELECT
    # --------------------------
    def select_row(self, event):
        item = self.tree.selection()
        if not item: return

        vals = self.tree.item(item[0])["values"]

        self.selected_id = vals[0]

        self.e_market.delete(0,"end"); self.e_market.insert(0, vals[1])
        self.e_open.delete(0,"end"); self.e_open.insert(0, vals[2])
        self.e_tp.delete(0,"end"); self.e_tp.insert(0, vals[3])
        self.e_sl.delete(0,"end"); self.e_sl.insert(0, vals[4])
        self.e_lot.delete(0,"end"); self.e_lot.insert(0, vals[5])
        self.side_var.set(vals[6])
        self.e_note.delete(0,"end"); self.e_note.insert(0, vals[8])

    # --------------------------
    # FILTER + CSV
    # --------------------------
    def parse_date(self, s):
        s = s.strip()
        if not s: return None
        try:
            datetime.datetime.strptime(s, "%Y-%m-%d")
            return s
        except:
            messagebox.showerror("Format Salah", "Gunakan format YYYY-MM-DD")
            return None

    def load_table(self):
        d1 = self.parse_date(self.f_from.get()) if hasattr(self, "f_from") else None
        d2 = self.parse_date(self.f_to.get()) if hasattr(self, "f_to") else None

        rows = fetch_notes(self.user_id, d1, d2)

        for r in self.tree.get_children():
            self.tree.delete(r)

        total = 0
        for row in rows:
            self.tree.insert("", "end", values=row)
            total += row[7]

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
        if not path: return

        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ID","Market","Open","TP","SL","Lot","Side","P/L","Note","Timestamp"])
            w.writerows(rows)

        messagebox.showinfo("Sukses", f"CSV disimpan di:\n{path}")

    # --------------------------
    # LOGOUT
    # --------------------------
    def logout(self):
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
