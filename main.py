from core.cve_engine import CVEEngine
from core.db_manager import DatabaseManager
from core.scanner import PortScanner

def run_pipeline(target_ip, ports_to_scan):
    print("Initializing database...")
    db = DatabaseManager()
    db.init_db()
    scan_id = db.save_scan(target_ip)
    print(f"Scan record created with ID: {scan_id}")
    scanner = PortScanner(target_ip = target_ip)
    cve_engine = CVEEngine()
    all_findings = []
    print(f"Starting port scan against {target_ip}...\n")
    for port in ports_to_scan:
        if scanner.scan_port(port):
            banner = scanner.grab_banner(port)
            print(f"Port {port} is OPEN | Service: {banner}")
            cves = cve_engine.fetch_cves(banner, limit=2)
            if cves:
                for cve in cves:
                    print(f"-> Vulnerability: {cve['cve_id']} (CVSS: {cve['cvss']})")
                    all_findings.append(
                        {
                            "port" : port,
                            "service" : banner,
                            "cve_id" : cve["cve_id"],
                            "cvss" : cve["cvss"],
                            "summary" : cve["summary"],
                        }
                    )
            else:
                all_findings.append(
                    {
                        "port" : port,
                        "service" : banner,
                        "cve_id" : None,
                        "cvss" : None,
                        "summary" : "NO CVEs identified or unknown service banner",
                    }
                )
    if all_findings:
        db.save_vulnerabilities(scan_id, all_findings)
        print(f"Successfully saved {len(all_findings)} records to the database.")
    else:
        print("\nNo open ports detected.")

if __name__ == "__main__":
    TARGET = "127.0.0.1"
    PORTS = [21, 22, 80,443, 8080]
    run_pipeline(target_ip = TARGET, ports_to_scan = PORTS)