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
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            raspuns = s.recv(1024).decode("utf-8", errors="ignore")
            s.close()
            if raspuns:
                return raspuns.split("\n")[0]
            return "Unknown service"
        except Exception:
            return "Unknown service"
