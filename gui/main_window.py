import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import logging
import time
from security.tls_manager import TLSManager
from security.config_auditor import ConfigAuditor
from ftp_server.user_manager import FTPUserManager
from security.log_watcher import LogWatcher

class MainApplication(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Secure Configuration Framework Dashboard")
        self.geometry("1000x850")
        
        self.tls_manager = TLSManager()
        self.auditor = ConfigAuditor()
        self.user_manager = FTPUserManager()
        self.log_watcher = LogWatcher()
        
        self.servers = {
            "web": {"running": False, "thread": None},
            "ftps": {"running": False, "thread": None},
            "sftp": {"running": False, "thread": None}
        }
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Unified Premium Palette (matching web CSS)
        self.bg_color = '#09090b'      # Main background
        self.secondary_bg = '#18181b'  # Cards / Panels
        self.accent = '#0a84ff'        # Accent blue
        self.text_color = '#f4f4f5'    # Primary text
        self.text_secondary = '#a1a1aa'# Secondary text
        
        self.configure(bg=self.bg_color)
        
        # Fundamental styles
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.text_color, font=("SF Pro Display", 11))
        self.style.configure("Header.TLabel", font=("SF Pro Display", 28, "bold"), foreground=self.text_color)
        self.style.configure("SubHeader.TLabel", font=("SF Pro Display", 15), foreground=self.text_secondary)
        
        # Tabs
        self.style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.secondary_bg, foreground=self.text_secondary, padding=[24, 12], font=("SF Pro Display", 11, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", self.bg_color)], foreground=[("selected", self.accent)])
        
        # Buttons
        self.style.configure("TButton", font=("SF Pro Text", 10, "bold"), padding=10, background=self.secondary_bg, foreground=self.text_color)
        self.style.map("TButton", background=[("active", self.accent)], foreground=[("active", "white")])
        
        # Treeviews (Tables for Users, Audits, Logs)
        self.style.configure("Treeview", background=self.secondary_bg, foreground=self.text_color, fieldbackground=self.secondary_bg, borderwidth=0, font=("SF Pro Text", 10))
        self.style.configure("Treeview.Heading", background=self.bg_color, foreground=self.text_secondary, font=("SF Pro Text", 10, "bold"), borderwidth=0, padding=5)
        self.style.map("Treeview", background=[("selected", self.accent)], foreground=[("selected", "white")])
        
        self.create_widgets()
        self.setup_logging()

    def create_widgets(self):
        # Header Section
        self.header_frame = ttk.Frame(self)
        self.header_frame.pack(fill="x", padx=20, pady=20)
        
        ttk.Label(self.header_frame, text="SECURE FRAMEWORK", style="Header.TLabel").pack(side="left")
        ttk.Label(self.header_frame, text="MANAGEMENT CONSOLE", style="SubHeader.TLabel").pack(side="left", padx=15, pady=(5, 0))
        
        # Notebook for multiple panels
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Panel 1: Server Control
        self.panel_control = ttk.Frame(self.notebook)
        self.notebook.add(self.panel_control, text="Server Control")
        self.setup_control_panel()
        
        # Panel 2: Live Log Viewer
        self.panel_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.panel_logs, text="Live Logs")
        self.setup_log_panel()
        
        # Panel 3: User Management
        self.panel_users = ttk.Frame(self.notebook)
        self.notebook.add(self.panel_users, text="Users")
        self.setup_user_panel()
        
        # Panel 4: TLS Manager
        self.panel_tls = ttk.Frame(self.notebook)
        self.notebook.add(self.panel_tls, text="Certificates")
        self.setup_tls_panel()
        
        # Panel 5: Security Audit
        self.panel_audit = ttk.Frame(self.notebook)
        self.notebook.add(self.panel_audit, text="Audit")
        self.setup_audit_panel()

        # Panel 6: Blocked IPs
        self.panel_blocks = ttk.Frame(self.notebook)
        self.notebook.add(self.panel_blocks, text="Blocked IPs")
        self.setup_blocks_panel()

    def setup_control_panel(self):
        self.service_widgets = {}
        services = [
            ("web", "Flask Web Server", 5443),
            ("ftps", "FTPS Server", 990),
            ("sftp", "SFTP Server", 2222)
        ]
        
        for i, (key, name, port) in enumerate(services):
            ttk.Label(self.panel_control, text=f"{name} (Port: {port})").grid(row=i, column=0, padx=20, pady=20, sticky="w")
            
            status_lbl = ttk.Label(self.panel_control, text="Stopped", foreground="#ef4444")
            status_lbl.grid(row=i, column=1, padx=20, pady=20)
            
            start_btn = ttk.Button(self.panel_control, text="Start", command=lambda k=key: self.toggle_server(k, True))
            start_btn.grid(row=i, column=2, padx=10, pady=20)
            
            stop_btn = ttk.Button(self.panel_control, text="Stop", state="disabled", command=lambda k=key: self.toggle_server(k, False))
            stop_btn.grid(row=i, column=3, padx=10, pady=20)
            
            self.service_widgets[key] = {"status": status_lbl, "start": start_btn, "stop": stop_btn}

    def toggle_server(self, key, start):
        if start:
            logging.info(f"Initiating start for {key} server...")
            # Here you would actually start the server thread
            self.servers[key]["running"] = True
            self.service_widgets[key]["status"].config(text="Running", foreground="#10b981")
            self.service_widgets[key]["start"].config(state="disabled")
            self.service_widgets[key]["stop"].config(state="normal")
        else:
            logging.info(f"Initiating stop for {key} server...")
            self.servers[key]["running"] = False
            self.service_widgets[key]["status"].config(text="Stopped", foreground="#ef4444")
            self.service_widgets[key]["start"].config(state="normal")
            self.service_widgets[key]["stop"].config(state="disabled")

    def setup_user_panel(self):
        self.user_tree = ttk.Treeview(self.panel_users, columns=("Username", "Home", "Role"), show="headings")
        self.user_tree.heading("Username", text="Username")
        self.user_tree.heading("Home", text="Home Directory")
        self.user_tree.heading("Role", text="Role")
        self.user_tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        btn_frame = ttk.Frame(self.panel_users)
        btn_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(btn_frame, text="Add User", command=self.add_user_dialog).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Refresh", command=self.refresh_users).pack(side="left", padx=5)

    def add_user_dialog(self):
        # Implementation of a simple pop-up for user creation
        messagebox.showinfo("Add User", "User management via GUI coming soon (Use CLI/UserManager for now)")

    def refresh_users(self):
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        users = self.user_manager.get_all_users()
        for u in users:
            self.user_tree.insert("", "end", values=(u['username'], u['home_dir'], u['role']))

    def setup_tls_panel(self):
        self.tls_status_lbl = ttk.Label(self.panel_tls, text="Checking status...", font=("Inter", 12))
        self.tls_status_lbl.pack(pady=20)
        
        ttk.Button(self.panel_tls, text="Generate/Renew Certificate", command=self.renew_cert).pack(pady=10)
        self.refresh_tls_status()

    def renew_cert(self):
        self.tls_manager.generate_self_signed_cert()
        self.refresh_tls_status()
        messagebox.showinfo("Success", "New self-signed certificate generated.")

    def refresh_tls_status(self):
        status, expiry = self.tls_manager.get_cert_status()
        color = "#10b981" if status == "Valid" else "#ef4444"
        self.tls_status_lbl.config(text=f"Status: {status}\nExpiry: {expiry}", foreground=color)

    def setup_audit_panel(self):
        self.audit_btn = ttk.Button(self.panel_audit, text="Run Security Audit", command=self.run_audit)
        self.audit_btn.pack(pady=20)
        
        self.audit_tree = ttk.Treeview(self.panel_audit, columns=("File", "Status", "Reason"), show="headings")
        self.audit_tree.heading("File", text="File")
        self.audit_tree.heading("Status", text="Status")
        self.audit_tree.heading("Reason", text="Reason")
        self.audit_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def run_audit(self):
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        
        # Ensure baseline exists for test
        if not os.path.exists(self.auditor.baseline_file):
            self.auditor.generate_baseline()
            
        audit = self.auditor.run_audit()
        for res in audit.get('results', []):
            self.audit_tree.insert("", "end", values=(res['file'], res['status'], res['reason']))

    def setup_blocks_panel(self):
        self.block_tree = ttk.Treeview(self.panel_blocks, columns=("IP", "Expiry"), show="headings")
        self.block_tree.heading("IP", text="IP Address")
        self.block_tree.heading("Expiry", text="Expires At")
        self.block_tree.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Button(self.panel_blocks, text="Refresh", command=self.refresh_blocks).pack(pady=5)

    def refresh_blocks(self):
        for item in self.block_tree.get_children():
            self.block_tree.delete(item)
        blocks = self.log_watcher.get_blocked_list()
        for ip, expiry in blocks.items():
            self.block_tree.insert("", "end", values=(ip, time.ctime(expiry)))

    def setup_log_panel(self):
        self.log_display = scrolledtext.ScrolledText(self.panel_logs, bg="#1e293b", fg="#94a3b8", font=("Courier", 10))
        self.log_display.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_logging(self):
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget

            def emit(self, record):
                msg = self.format(record)
                self.text_widget.configure(state='normal')
                self.text_widget.insert('end', msg + '\n')
                self.text_widget.configure(state='disabled')
                self.text_widget.yview('end')

        handler = TextHandler(self.log_display)
        logging.getLogger().addHandler(handler)
        logging.info("GUI Logging started.")

if __name__ == "__main__":
    app = MainApplication()
    app.mainloop()
