import argparse
from core.cve_engine import CVEEngine
from core.db_manager import DatabaseManager
from core.scanner import PortScanner


def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        elif part:
            ports.append(int(part))
    return sorted(list(set(ports)))


def show_history(db):
    scans = db.get_all_scans()
    if not scans:
        print("\nNo scan records found.")
        return

    print("\n--- Scan History ---")
    print(f"{'ID':<6} | {'Target IP':<16} | {'Scan Date'}")
    print("-" * 45)
    for scan in scans:
        print(f"{scan[0]:<6} | {scan[1]:<16} | {scan[2]}")
    print("-" * 45 + "\n")


def show_report(db, scan_id):
    results = db.get_scan_vulnerabilities(scan_id)
    if not results:
        print(f"\nNo records found for scan_id: {scan_id}")
        return

    print(f"\n--- Detailed Report for Scan ID {scan_id} ---")
    print(
        f"{'Port':<6} | {'Service':<16} | {'CVE ID':<16} | {'CVSS':<6} |"
        " {'Summary'}"
    )
    print("-" * 90)
    for row in results:
        port, service, cve_id, cvss, summary = row
        cve_str = cve_id if cve_id else "N/A"
        cvss_str = str(cvss) if cvss else "N/A"
        summary_str = (
            (summary[:40] + "...")
            if summary and len(summary) > 40
            else (summary or "")
        )
        print(
            f"{port:<6} | {service:<16} | {cve_str:<16} | {cvss_str:<6} |"
            f" {summary_str}"
        )
    print("-" * 90 + "\n")


def run_pipeline(target_ip, ports_to_scan, threads=30):
    print("Initializing database...")
    db = DatabaseManager()
    db.init_db()
    scan_id = db.save_scan(target_ip)
    print(f"Scan record created with ID: {scan_id}")

    scanner = PortScanner(target_ip=target_ip)
    cve_engine = CVEEngine()
    all_findings = []

    print(
        f"Scanning {len(ports_to_scan)} ports against {target_ip} using"
        f" {threads} threads...\n"
    )
    open_ports = scanner.scan_ports_concurrent(
        ports_to_scan, max_threads=threads
    )

    if not open_ports:
        print("No open ports detected.")
        return

    print(f"Discovered {len(open_ports)} open port(s): {open_ports}\n")

    for port in open_ports:
        banner = scanner.grab_banner(port)
        print(f"Port {port} is OPEN | Service: {banner}")
        cves = cve_engine.fetch_cves(banner, limit=2)
        if cves:
            for cve in cves:
                print(
                    f"-> Vulnerability: {cve['cve_id']} (CVSS: {cve['cvss']})"
                )
                all_findings.append(
                    {
                        "port": port,
                        "service": banner,
                        "cve_id": cve["cve_id"],
                        "cvss": cve["cvss"],
                        "summary": cve["summary"],
                    }
                )
        else:
            all_findings.append(
                {
                    "port": port,
                    "service": banner,
                    "cve_id": None,
                    "cvss": None,
                    "summary": "NO CVEs identified or unknown service banner",
                }
            )

    if all_findings:
        db.save_vulnerabilities(scan_id, all_findings)
        print(
            f"\nSuccessfully saved {len(all_findings)} records to the database."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VulnScope Network & CVE Scanner"
    )
    parser.add_argument(
        "-t",
        "--target",
        default="127.0.0.1",
        help="Target IP address to scan (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="21,22,80,443,8080",
        help=(
            "Ports or ranges to scan (default: 21,22,80,443,8080 or 8000-8100)"
        ),
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=30,
        help="Number of concurrent scanning threads (default: 30)",
    )
    parser.add_argument(
        "--history", action="store_true", help="Show previous scan history"
    )
    parser.add_argument(
        "--report",
        type=int,
        help="Display vulnerability report for a specific scan ID",
    )

    args = parser.parse_args()
    db = DatabaseManager()

    if args.history:
        show_history(db)
    elif args.report:
        show_report(db, args.report)
    else:
        selected_ports = parse_ports(args.ports)
        run_pipeline(
            target_ip=args.target,
            ports_to_scan=selected_ports,
            threads=args.threads,
        )