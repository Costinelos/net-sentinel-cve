import os
import sqlite3


class DatabaseManager:

    def __init__(self, db_name="vulnscope.db"):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_name = os.path.join(base_dir, db_name)

    def init_db(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute(
            """CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""
        )

        cursor.execute(
            """CREATE TABLE IF NOT EXISTS vulnerabilities(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            cve_id TEXT,
            cvss REAL,
            summary TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id))"""
        )

        conn.commit()
        conn.close()

    def save_scan(self, target_ip):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target_ip) VALUES (?)", (target_ip,)
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def save_vulnerabilities(self, scan_id, results):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        records = []
        for item in results:
            records.append(
                (
                    scan_id,
                    item.get("port"),
                    item.get("service"),
                    item.get("cve_id"),
                    item.get("cvss"),
                    item.get("summary"),
                )
            )
        query = "INSERT INTO vulnerabilities (scan_id, port, service, cve_id, cvss, summary) VALUES (?,?,?,?,?,?)"
        cursor.executemany(query, records)
        conn.commit()
        conn.close()

    def get_scan_vulnerabilities(self, scan_id):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT port, service, cve_id, cvss, summary FROM"
            " vulnerabilities WHERE scan_id = ?",
            (scan_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_all_scans(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target_ip, scan_date FROM scans ORDER BY scan_date"
            " DESC"
        )
        scans = cursor.fetchall()
        conn.close()
        return scans


if __name__ == "__main__":
    db = DatabaseManager()
    db.init_db()

    scan_id = db.save_scan("192.168.1.100")
    print(f"Scan saved with ID: {scan_id}")

    mock_results = [
        {
            "port": 80,
            "service": "Apache 2.4.49",
            "cve_id": "CVE-2021-41773",
            "cvss": 7.5,
            "summary": "Path traversal flaw in Apache HTTP Server 2.4.49",
        },
        {
            "port": 22,
            "service": "OpenSSH 8.2p1",
            "cve_id": None,
            "cvss": None,
            "summary": None,
        },
    ]
    db.save_vulnerabilities(scan_id, mock_results)
    print("Vulnerabilities saved successfully!")

    scan_history = db.get_all_scans()
    print(f"Scan history from DB: {scan_history}")

    results_14 = db.get_scan_vulnerabilities(14)
    print(f"Rezultate pentru scan_id 14: {results_14}")