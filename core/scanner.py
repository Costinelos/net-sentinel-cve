import socket

class PortScanner:
    def __init__(self, target_ip, time_out = 1.5):
        self.target_ip = target_ip
        self.time_out = time_out

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
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
                raw_data = s.recv(1024)
            s.close()
            if raw_data:
                decoded = raw_data.decode("utf-8", errors="ignore").strip()
                for line in decoded.splitlines():
                    cleaned_line = line.strip()
                    if cleaned_line:
                        return cleaned_line
            return "Unknown service"
        except Exception:
            return "Unknown service"
