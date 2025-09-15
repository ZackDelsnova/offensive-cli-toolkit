from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
import socket
import ssl

RESULT_DIR = "results\\port_scanner_results"
os.makedirs(RESULT_DIR, exist_ok=True)

COMMON_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP (server)", 68: "DHCP (client)", 69: "TFTP", 80: "HTTP", 110: "POP3",
    123: "NTP", 137: "NetBIOS", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 514: "Syslog", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-alt"
}

TCP_TIMEOUT = 0.6
UDP_TIMEOUT = 1.0

def tcp_connect(ip, port, timeout=TCP_TIMEOUT):
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((ip, port))
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None

# banner grabbing, for http send HEAD others try recv()
def grab_banner_tcp(sock, ip, port, timeout=1.0):
    sock.settimeout(timeout)
    banner = ""
    try:
        if port in (80, 8080):
            req = "HEAD / HTTP/1.1\r\nHost: {}\r\nConnections: close\r\n\r\n".format(ip)
            sock.sendall(req.encode())
            data = sock.recv(4096)
            banner = data.decode(errors="replace").splitlines()[0:8]
            return "\n".join(banner)
        elif port == 443:
            # tls = transport layer security
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode == ssl.CERT_NONE
                ssock = ctx.wrap_socket(sock, server_hostname=ip)
                cert = ssock.getpeercert()
                ssock.settimeout(1.0)
                return f"TLS cert subject: {cert.get('subject')}"
            except Exception as e:
                return f"TLS handshake failed: {e}"
        else:
            # generic banner
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
            try:
                data = sock.recv(2048)
                if not data:
                    return "<no-banner-received>"
                
                text = data[:240].decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
                return text
            except Exception:
                return "<no-banner / recv-timed-out>"
    except Exception as e:
        return f"<banner-error: {e}>"
    finally:
        try:
            sock.close()
        except Exception:
            pass

# returns (port, true/false, service_hint, banner)
def scan_tcp_worker(ip, port):
    sock = tcp_connect(ip, port)
    if not sock:
        return (port, False, COMMON_SERVICES.get(port, ""), "")

    banner = grab_banner_tcp(sock, ip, port)
    return (port, True, COMMON_SERVICES.get(port, ""), banner)

# tcp port scanning concurrently n return list of dict for open port
def scan_tcp_ports(target, start=1, end=1024, workers=100):
    print(f"tcp scan {target} ports {start}-{end} (threads={workers})")
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_tcp_worker, target, p): p for p in range(start, end + 1)}
        for fut in as_completed(futs):
            try:
                port, is_open, hint, banner = fut.result()
                if is_open:
                    print(f"open tcp: {target}:{port}   ({hint})")
                    if banner:
                        short = banner.splitlines()[0] if "\n" in banner else banner
                        print("    ->", short)
                    open_ports.append({"port": port, "protocol": "tcp", "service_hint": hint, "banner": banner})
            except Exception as e:
                print(f"worker error: {e}")
    return open_ports

def udp_probe(ip, port, timeout=UDP_TIMEOUT):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00", (ip, port))
        data, addr = s.recvfrom(4096)
        text = data[:240].decode("utf-8", errors="replace")
        return (port, True, COMMON_SERVICES.get(port, ""), text)
    except socket.timeout:
        return (port, None, COMMON_SERVICES.get(port, ""), "")
    except Exception as e:
        return (port, False, COMMON_SERVICES.get(port, ""), str(e))
    finally:
        try:
            s.close()
        except:
            pass

def scan_udp_ports(target, start=1, end=1024, workers=50):
    print(f"udp scan {target} port {start}-{end} (threads={workers}) -- udp results are best-effort")
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(udp_probe, target, p): p for p in range(start, end + 1)}
        for fut in as_completed(futs):
            try:
                port, state, hint, resp = fut.result()
                if state is True:
                    print(f"open udp: {target}:{port} ({hint})")
                    if resp:
                        print("    ->", resp.splitlines()[0])
                    results.append({"port": port, "protocol": "udp", "service_hint": hint, "response":resp})
                elif state is None:
                    print(f"filtered/no response udp: {target}:{port}")
                else:
                    pass
            except Exception as e:
                print(f"udp worker erro: {e}")
    return results

def start_scan():
    target = input("enter ip address or hostname: ").strip()
    try:
        resolved = socket.gethostbyname(target)
    except Exception:
        resolved = target

    try:
        start_port = int(input("start port (default 1): ") or "1")
        end_port = int(input("end port (default 1024): ") or "1024")
    except ValueError:
        print("invalid port numbers")
        return
    
    do_udp = input("also scan udp? (y/n): ").strip().lower() == "y"

    tcp_results = scan_tcp_ports(resolved, start=start_port, end=end_port, workers=200)
    udp_results = []
    if do_udp:
        udp_results = scan_udp_ports(resolved, start=start_port, end=end_port, workers=100)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fn = os.path.join(RESULT_DIR, f"scan_{resolved}_{start_port}-{end_port}_{ts}.txt")
    with open(fn, "w", encoding="utf-8") as f:
        f.write(f"scan target: {target} (resolved: {resolved})\n")
        f.write(f"ports: {start_port}-{end_port} tcp timeout: {TCP_TIMEOUT} udp timeout: {UDP_TIMEOUT}")
        f.write("\ntcp open ports:\n")
        for r in tcp_results:
            f.write(f"  {r['port']}/tcp  ({r['service_hint']})\n")
            if r.get("banner"):
                f.write(f"    banner: {r['banner']}")
        f.write("\nupd result (best-effort):\n")
        for r in udp_results:
            f.write(f"  {r['port']}/udp  ({r['service_hint']})  response: {r.get('response', '')}\n")
    print(f"results saved to {fn}")
