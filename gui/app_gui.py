import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cve_engine import CVEEngine
from core.db_manager import DatabaseManager
from core.scanner import PortScanner


class VulnerabilityScannerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("VulnScope | Vulnerability & Port Scanner")
        self.root.geometry("1000x680")
        self.root.minsize(850, 500)

        self.db = DatabaseManager()
        self.db.init_db()

        self._build_inputs()
        self._build_table()
        self._build_detail_box()
        self._build_status_bar()

    def _build_inputs(self):
        input_frame = ttk.LabelFrame(
            self.root, text=" Scan Configuration ", padding=10
        )
        input_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(input_frame, text="Target IP / Host:").grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )
        self.entry_ip = ttk.Entry(input_frame, width=20)
        self.entry_ip.insert(0, "127.0.0.1")
        self.entry_ip.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="Ports:").grid(
            row=0, column=2, padx=5, pady=5, sticky="w"
        )
        self.entry_ports = ttk.Entry(input_frame, width=24)
        self.entry_ports.insert(0, "80, 443, 8080")
        self.entry_ports.grid(row=0, column=3, padx=5, pady=5)

        self.btn_scan = ttk.Button(
            input_frame, text="Start Scan", command=self.start_scan_thread
        )
        self.btn_scan.grid(row=0, column=4, padx=10, pady=5)

        self.btn_history = ttk.Button(
            input_frame, text="View History", command=self.open_history_window
        )
        self.btn_history.grid(row=0, column=5, padx=5, pady=5)

    def _build_table(self):
        table_container = ttk.Frame(self.root)
        table_container.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("port", "service", "cve_id", "cvss", "summary")
        self.tree = ttk.Treeview(
            table_container, columns=columns, show="headings"
        )

        self.tree.heading("port", text="Port")
        self.tree.heading("service", text="Service Banner")
        self.tree.heading("cve_id", text="CVE ID")
        self.tree.heading("cvss", text="CVSS")
        self.tree.heading("summary", text="Vulnerability Summary")

        self.tree.column("port", width=70, anchor="center")
        self.tree.column("service", width=180)
        self.tree.column("cve_id", width=130, anchor="center")
        self.tree.column("cvss", width=60, anchor="center")
        self.tree.column("summary", width=600)

        self.tree.tag_configure("critical", background="#ffd6d6")
        self.tree.tag_configure("medium", background="#fff3cd")

        scroll_y = ttk.Scrollbar(
            table_container, orient="vertical", command=self.tree.yview
        )
        scroll_x = ttk.Scrollbar(
            table_container, orient="horizontal", command=self.tree.xview
        )
        self.tree.configure(
            yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set
        )

        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        table_container.rowconfigure(0, weight=1)
        table_container.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

    def _build_detail_box(self):
        detail_frame = ttk.LabelFrame(
            self.root, text=" Selected Vulnerability Details ", padding=5
        )
        detail_frame.pack(fill="x", padx=10, pady=5)

        self.detail_text = tk.Text(
            detail_frame, height=5, wrap="word", relief="flat"
        )
        self.detail_text.pack(fill="both", expand=True)
        self.detail_text.insert(
            "1.0",
            "Click on any row in the table above to view full description.",
        )
        self.detail_text.config(state="disabled")

    def _on_row_select(self, event):
        selected_item = self.tree.focus()
        if not selected_item:
            return
        values = self.tree.item(selected_item, "values")
        if values and len(values) >= 5:
            full_summary = values[4]
            cve_id = values[2]
            cvss = values[3]

            self.detail_text.config(state="normal")
            self.detail_text.delete("1.0", "end")
            self.detail_text.insert(
                "end", f"[{cve_id}] (CVSS: {cvss})\n\n{full_summary}"
            )
            self.detail_text.config(state="disabled")

    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w",
            padding=5,
        )
        status_bar.pack(side="bottom", fill="x")

    def parse_ports(self, port_str):
        ports = []
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            elif part:
                ports.append(int(part))
        return sorted(list(set(ports)))

    def start_scan_thread(self):
        ip = self.entry_ip.get().strip()
        ports_raw = self.entry_ports.get().strip()

        if not ip or not ports_raw:
            messagebox.showwarning(
                "Input Error", "Please provide both a target IP and ports."
            )
            return

        try:
            ports = self.parse_ports(ports_raw)
        except ValueError:
            messagebox.showerror(
                "Format Error",
                "Invalid port format. Use comma-separated values or ranges"
                " (e.g., 80,443 or 8000-8100).",
            )
            return

        self.btn_scan.config(state="disabled")
        for row in self.tree.get_children():
            self.tree.delete(row)

        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert(
            "1.0", "Scanning in progress... Select a result when completed."
        )
        self.detail_text.config(state="disabled")

        thread = threading.Thread(
            target=self._run_scan, args=(ip, ports), daemon=True
        )
        thread.start()

    def _run_scan(self, ip, ports):
        self.status_var.set(f"Scanning {len(ports)} port(s) against {ip}...")
        scan_id = self.db.save_scan(ip)

        scanner = PortScanner(target=ip)
        cve_engine = CVEEngine()
        findings = []

        open_ports = scanner.scan_ports_concurrent(ports, max_threads=30)

        if not open_ports:
            self.status_var.set("Completed: No open ports discovered.")
            self.btn_scan.config(state="normal")
            return

        for port in open_ports:
            self.status_var.set(
                f"Extracting banner & fetching CVEs for port {port}..."
            )
            banner = scanner.grab_banner(port)
            cves = cve_engine.fetch_cves(banner, limit=3)

            if cves:
                for item in cves:
                    findings.append(
                        {
                            "port": port,
                            "service": banner,
                            "cve_id": item["cve_id"],
                            "cvss": item["cvss"],
                            "summary": item["summary"],
                        }
                    )
                    score = item["cvss"] or 0
                    tag = (
                        "critical"
                        if score >= 7.0
                        else ("medium" if score >= 4.0 else "")
                    )
                    self.tree.insert(
                        "",
                        "end",
                        values=(
                            port,
                            banner,
                            item["cve_id"],
                            item["cvss"],
                            item["summary"],
                        ),
                        tags=(tag,),
                    )
            else:
                findings.append(
                    {
                        "port": port,
                        "service": banner,
                        "cve_id": "-",
                        "cvss": "-",
                        "summary": "No known CVEs identified",
                    }
                )
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        port,
                        banner,
                        "-",
                        "-",
                        "No known CVEs identified",
                    ),
                )

        if findings:
            self.db.save_vulnerabilities(scan_id, findings)

        self.status_var.set(
            f"Scan completed. Results saved to database (Scan ID: {scan_id})."
        )
        self.btn_scan.config(state="normal")

    def open_history_window(self):
        history_win = tk.Toplevel(self.root)
        history_win.title("Scan History")
        history_win.geometry("500x350")

        cols = ("id", "target", "date")
        tree_hist = ttk.Treeview(history_win, columns=cols, show="headings")
        tree_hist.heading("id", text="Scan ID")
        tree_hist.heading("target", text="Target IP")
        tree_hist.heading("date", text="Date")

        tree_hist.column("id", width=70, anchor="center")
        tree_hist.column("target", width=150)
        tree_hist.column("date", width=240)

        scans = self.db.get_all_scans()
        for s in scans:
            tree_hist.insert("", "end", values=(s[0], s[1], s[2]))

        tree_hist.pack(fill="both", expand=True, padx=10, pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerGUI(root)
    root.mainloop()