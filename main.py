# main.py
"""
Main GUI and orchestration for Windows Artifacts Parser.
Includes:
- parsing flows for prefetch/lnk/recycle/shellbags (calls out to parsers modules)
- DB integration (uses open_db/execute_with_retry if available)
- Report generation (PDF) with charts
- CSV export
"""

import os
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tempfile
import socket

# Import core_logic to centralize logic
import core_logic

# Use Agg backend for non-GUI chart rendering
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Try to import db_utils either in package or root
try:
    from db.db_utils import open_db, execute_with_retry
except Exception:
    try:
        from db_utils import open_db, execute_with_retry
    except Exception:
        open_db = None
        execute_with_retry = None

# Import parsers and schema (try package imports then fallbacks)
try:
    from parsers import report_gen
except Exception:
    # fallback: maybe modules are at top-level
    import report_gen

# schema functions - attempt package then fallback
try:
    from db.schema import init_db, query_artifacts
except Exception:
    try:
        from schema import init_db, query_artifacts
    except Exception:
        # Last resort: import db.schema as module
        import db.schema as schema
        init_db = schema.init_db
        query_artifacts = schema.query_artifacts

DB_PATH = core_logic.DB_PATH


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Windows Artifacts Parser {core_logic.TOOL_VERSION}")
        self.geometry("1100x700")
        self.resizable(True, True)
        self.setup_styles()
        # Initialize DB via core_logic or directly if needed, but core_logic does it on import
        # We ensure it's initialized here just in case
        if init_db:
            init_db(DB_PATH)
        self.create_widgets()

    def setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        BG_COLOR = "#FBFBFA"
        TEXT_COLOR = "#090E0A"
        MUTED_GREEN_GRAY = "#5C635B"
        GOLD_ACCENT = "#B09861"
        LIGHT_BEIGE_HOVER = "#CACDAE"
        SEPARATOR_COLOR = "#EAEAEA"
        self.configure(background=BG_COLOR)
        style.configure(".", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 9))
        style.configure("TFrame", background=BG_COLOR)
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR)
        style.configure("TButton", background=GOLD_ACCENT, foreground=BG_COLOR, font=("Segoe UI", 9, "bold"), borderwidth=0, padding=(14, 8))
        style.map("TButton", background=[("active", LIGHT_BEIGE_HOVER), ("hover", MUTED_GREEN_GRAY)], foreground=[("active", TEXT_COLOR), ("hover", BG_COLOR)])
        style.configure("TEntry", fieldbackground="#FFFFFF", foreground=TEXT_COLOR, insertcolor=TEXT_COLOR, bordercolor=SEPARATOR_COLOR, borderwidth=1, padding=8)
        style.configure("Treeview", rowheight=30, fieldbackground=BG_COLOR, background=BG_COLOR, foreground=TEXT_COLOR, borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", background=BG_COLOR, foreground=MUTED_GREEN_GRAY, font=("Segoe UI", 10, "bold"), padding=(10, 10), relief="flat", bordercolor=SEPARATOR_COLOR, borderwidth=1)
        self.tree_tags = {"odd": BG_COLOR, "even": "#F5F5F5", "hover": LIGHT_BEIGE_HOVER}

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=(20, 10))
        main_frame.pack(fill=tk.BOTH, expand=True)
        title_label = ttk.Label(main_frame, text="Windows Artifacts Parser", font=("Segoe UI", 20, "bold"), anchor="w")
        title_label.pack(fill=tk.X, pady=(0, 20))
        top = ttk.Frame(main_frame)
        top.pack(fill=tk.X, pady=(0, 15))
        self.path_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.path_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)
        ttk.Button(top, text="Browse...", command=self.browse_folder).pack(side=tk.LEFT, padx=(8, 4))
        ttk.Button(top, text="Parse Folder", command=self.parse_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Parse ShellBags", command=self.parse_shellbags).pack(side=tk.LEFT, padx=4)
        tree_container = ttk.Frame(main_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        cols = ("id", "type", "name", "path", "timestamp", "last_access", "extra")
        self.tree = ttk.Treeview(tree_container, columns=cols, show="headings")
        self.tree.tag_configure("oddrow", background=self.tree_tags["odd"])
        self.tree.tag_configure("evenrow", background=self.tree_tags["even"])
        self.tree.tag_configure("hover", background=self.tree_tags["hover"])
        self._hovered_item = None
        self.tree.bind("<Motion>", self._on_hover)
        self.tree.bind("<Leave>", self._on_leave)
        for c in cols:
            self.tree.heading(c, text=c.capitalize(), anchor=tk.W)
            self.tree.column(c, width=150 if c not in ("extra", "path") else 300, anchor=tk.W)
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)
        bottom = ttk.Frame(main_frame)
        bottom.pack(fill=tk.X, pady=(15, 0))
        ttk.Button(bottom, text="Correlate / Timeline", command=self.open_correlator).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Refresh", command=self.refresh_view).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Export to CSV", command=self.export_to_csv).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Export PDF Report", command=self.export_pdf_report).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Export Correlation PDF", command=lambda: self.export_correlation_pdf(None)).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Clear DB", command=self.clear_db).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Exit", command=self.destroy).pack(side=tk.RIGHT)
        self.refresh_view()

    # --- GUI hover helpers ---
    def _on_hover(self, event):
        item = self.tree.identify_row(event.y)
        if item != self._hovered_item:
            if self._hovered_item:
                tags = list(self.tree.item(self._hovered_item, "tags"))
                if "hover" in tags:
                    tags.remove("hover")
                    self.tree.item(self._hovered_item, tags=tags)
            if item:
                tags = list(self.tree.item(item, "tags"))
                if "hover" not in tags:
                    tags.append("hover")
                self.tree.item(item, tags=tags)
            self._hovered_item = item

    def _on_leave(self, event):
        if self._hovered_item:
            tags = list(self.tree.item(self._hovered_item, "tags"))
            if "hover" in tags:
                tags.remove("hover")
                self.tree.item(self._hovered_item, tags=tags)
        self._hovered_item = None

    # --- file/folder handling ---
    def browse_folder(self):
        d = filedialog.askdirectory(title="Select Folder Containing Artifacts")
        if d:
            self.path_var.set(d)

    def parse_selected(self):
        folder = self.path_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please choose a valid directory to parse.")
            return
        threading.Thread(target=self._parse_folder, args=(folder,), daemon=True).start()
        messagebox.showinfo("Parsing Started", "Parsing in background. Click Refresh when finished.")

    def _parse_folder(self, folder):
        try:
            result = core_logic.parse_folder_core(folder)
            if result.get("status") == "error":
                print(f"[!] Error: {result.get('message')}")
            else:
                print(f"[+] {result.get('message')}")
        except Exception as e:
            print(f"[!] Failed to parse folder via core_logic: {e}")
        
        self.after(0, lambda: messagebox.showinfo("Parsing Complete", f"Finished parsing folder: {folder}"))
        self.after(0, self.refresh_view)

    # --- ShellBags parse worker ---
    def parse_shellbags(self):
        if hasattr(self, "_shellbags_thread") and self._shellbags_thread.is_alive():
            messagebox.showwarning("ShellBags", "ShellBags parsing is already running.")
            return
        self._shellbags_thread = threading.Thread(target=self._parse_shellbags_worker, daemon=True)
        self._shellbags_thread.start()
        messagebox.showinfo("ShellBags", "Parsing ShellBags in background. Click Refresh when finished.")

    def _parse_shellbags_worker(self):
        try:
            result = core_logic.parse_shellbags_core()
            msg = result.get("message", "")
            if result.get("status") == "error":
                self.after(0, lambda: messagebox.showerror("Error", msg))
            else:
                self.after(0, lambda: messagebox.showinfo("ShellBags", msg))
        except Exception as e:
            err_text = f"Failed to parse ShellBags:\n{e}"
            self.after(0, lambda msg=err_text: messagebox.showerror("Error", msg))
            print(f"[!] ShellBags worker error: {e}")
        
        self.after(0, self.refresh_view)

    # --- view / DB operations ---
    def refresh_view(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        # Use query_artifacts from db/schema which is what core_logic uses internally too
        # But we can also use core_logic.get_all_artifacts_json() if we want consistent formatting
        # However, query_artifacts returns sqlite3.Row objects which main.py expects
        # core_logic.get_all_artifacts_json returns dicts with ISO timestamps
        # Let's stick to query_artifacts for now as main.py logic expects it
        rows = query_artifacts(DB_PATH)
        for i, row in enumerate(rows):
            row = dict(row)
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            self.tree.insert("", tk.END, values=(row.get("id"), row.get("artifact_type"), row.get("name"), row.get("path"), row.get("timestamp"), row.get("last_access"), row.get("extra")), tags=(tag,))

    def clear_db(self):
        if messagebox.askyesno("Confirm", "Delete all artifacts from the database?"):
            result = core_logic.clear_database_core()
            if result.get("status") == "error":
                messagebox.showerror("Error", result.get("message"))
            self.refresh_view()

    # --- CSV export (NEW method) ---
    def export_to_csv(self):
        """
        Export all artifacts to CSV. Opens a SaveAs dialog for destination.
        """
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")], title="Export artifacts as CSV")
        if not path:
            return
        result = core_logic.generate_csv_report(path)
        if result.get("status") == "success":
            messagebox.showinfo("Export CSV", result.get("message"))
        else:
            messagebox.showerror("Export Error", result.get("message"))

    # --- PDF export with metadata + charts ---
    def export_pdf_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")], title="Export Artifacts Report as PDF")
        if not file_path:
            return
        try:
            # We can use core_logic.generate_pdf_report_core, but it expects 'report_details' dict
            # main.py didn't ask for details before. 
            # We can construct a basic details dict or just use the logic directly using core_logic helpers
            
            rows = core_logic.get_all_artifacts_json()
            metadata = core_logic.build_metadata(DB_PATH)
            
            # Since main.py didn't have input fields for Case ID etc, we leave them blank or default
            # metadata is already built
            
            tmp_dir = tempfile.mkdtemp(prefix="wab_report_")
            counts_png = os.path.join(tmp_dir, "counts.png")
            timeline_png = os.path.join(tmp_dir, "timeline.png")
            
            core_logic.make_counts_chart(rows, counts_png)
            core_logic.make_timeline_histogram(rows, timeline_png)
            
            metadata["chart_counts"] = counts_png
            metadata["chart_timeline"] = timeline_png
            
            report_gen.generate_pdf_report(DB_PATH, file_path, title=f"Artifacts Report ({socket.gethostname()})", metadata=metadata)
            messagebox.showinfo("Report Generated", f"PDF report successfully generated:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate PDF report:\n{e}")

    def export_correlation_pdf(self, parent_window=None):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")], title="Export Correlation Report to PDF", parent=parent_window)
        if not file_path:
            return
        try:
            rows = core_logic.get_all_artifacts_json()
            metadata = core_logic.build_metadata(DB_PATH)
            
            tmp_dir = tempfile.mkdtemp(prefix="wab_corr_")
            counts_png = os.path.join(tmp_dir, "counts_corr.png")
            timeline_png = os.path.join(tmp_dir, "timeline_corr.png")
            
            core_logic.make_counts_chart(rows, counts_png)
            core_logic.make_timeline_histogram(rows, timeline_png)
            
            metadata["chart_counts"] = counts_png
            metadata["chart_timeline"] = timeline_png
            
            report_gen.generate_correlation_pdf(DB_PATH, file_path, title=f"Correlation Report ({socket.gethostname()})", metadata=metadata)
            messagebox.showinfo("Report Generated", f"Correlation PDF successfully generated:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate correlation PDF:\n{e}")

    # --- Correlator UI ---
    def open_correlator(self):
        window = tk.Toplevel(self)
        window.title("Correlations / Timeline")
        window.geometry("1200x650")
        window.configure(background="#FBFBFA")
        main_frame = ttk.Frame(window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(6, 8))
        ttk.Button(toolbar, text="Export Correlation PDF", command=lambda: self.export_correlation_pdf(window)).pack(side=tk.LEFT)
        cols = ("time", "artifact", "detail", "anomaly")
        tree = ttk.Treeview(main_frame, columns=cols, show="headings", height=20)
        tree.heading("time", text="Timestamp", anchor=tk.W)
        tree.heading("artifact", text="Type", anchor=tk.W)
        tree.heading("detail", text="Detail", anchor=tk.W)
        tree.heading("anomaly", text="Anomaly", anchor=tk.W)
        tree.column("time", width=180, anchor=tk.W)
        tree.column("artifact", width=150, anchor=tk.W)
        tree.column("detail", width=700, anchor=tk.W)
        tree.column("anomaly", width=200, anchor=tk.W)
        vsb = ttk.Scrollbar(main_frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(main_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)
        tree.tag_configure("evenrow", background="#F5F5F5")
        tree.tag_configure("oddrow", background="#FBFBFA")

        # Attempt to import correlate_artifacts; support both styles
        try:
            from correlator import correlate_artifacts
        except Exception:
            try:
                # maybe the function expects a DB connection
                from correlator import correlate_artifacts
            except Exception as e:
                messagebox.showerror("Correlator Error", f"Failed to import correlator: {e}")
                return

        # Use core_logic.get_correlations_json() to get list of dicts
        # But wait, core_logic.get_correlations_json calls correlate_artifacts internally
        # Let's try to use core_logic if possible
        
        rows = []
        try:
            # If core_logic has the function exposed
            rows = core_logic.get_correlations_json()
        except Exception as e:
            # Fallback
            messagebox.showerror("Correlator Error", f"Correlator failed: {e}")
            return

        for i, r in enumerate(rows):
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            tree.insert("", tk.END, values=(r.get("timestamp") or "", r.get("artifact_type") or "", r.get("detail") or "", r.get("anomaly") or ""), tags=(tag,))


if __name__ == "__main__":
    app = App()
    app.mainloop()
