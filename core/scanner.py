from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from urllib.parse import urlparse


class PortScanner:

    def __init__(self, target, time_out=1.5):
        self.raw_target = target
        self.time_out = time_out
        self.target_ip = self._resolve_target(target)

    def _resolve_target(self, target):
        target = target.strip()
        if "://" in target:
            parsed = urlparse(target)
            target = parsed.hostname or target
        elif "/" in target:
            target = target.split("/")[0]

        if ":" in target:
            target = target.split(":")[0]

        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return target

    def scan_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.time_out)
        try:
            result = s.connect_ex((self.target_ip, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def grab_banner(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.time_out)
        try:
            s.connect((self.target_ip, port))
            try:
                raw_data = s.recv(1024)
            except socket.timeout:
                raw_data = None

            if not raw_data:
                request = (
                    f"HEAD / HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent:"
                    " VulnScope\r\nConnection: close\r\n\r\n"
                )
                s.sendall(request.encode())
                raw_data = s.recv(1024)
            s.close()

            if raw_data:
                decoded = raw_data.decode("utf-8", errors="ignore").strip()
                for line in decoded.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()

                first_line = decoded.splitlines()[0].strip()
                if not first_line.startswith("HTTP/"):
                    return first_line

            return "Unknown service"
        except Exception:
            return "Unknown service"

    def scan_ports_concurrent(self, ports, max_threads=30):
        open_ports = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port for port in ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)
        return sorted(open_ports)