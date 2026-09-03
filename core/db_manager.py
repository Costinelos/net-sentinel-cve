import sqlite3

class DatabaseManager:
    def __init__(self, db_name = "vulnscope.db"):
        self.db_name = db_name

    def init_db(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            cve_id TEXT,
            cvss REAL,
            summary TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id))""")

        conn.commit()
        conn.close()

    def save_scan(self, target_ip):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (target_ip) VALUES (?)", (target_ip,))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def save_vulnerabilities(self, scan_id, results):
        conn =sqlite3.connect(self.db_name)
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

    def get_all_scans(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT id, target_ip, scan_date FROM scans ORDER BY scan_date DESC")
        scans = cursor.fetchall()

        conn.close()
        return scans

if __name__ == "__main__":
    db = DatabaseManager()
    db.init_db()

    # 1. Test saving a new scan
    scan_id = db.save_scan("192.168.1.100")
    print(f"Scan saved with ID: {scan_id}")

    # 2. Test saving mock vulnerability results
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

    # 3. Test reading scan history
    scan_history = db.get_all_scans()
    print(f"Scan history from DB: {scan_history}")