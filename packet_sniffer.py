from datetime import datetime
from pathlib import Path
import psutil
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, Raw, get_if_list, conf
import socket
import traceback
from typing import Callable, Iterable, List, Optional

try:
    from scapy.all import get_windows_if_list
except:
    get_windows_if_list = None


def format_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

# returns a list of interfaces like eth0
def list_interface() -> List[str]:
    return get_if_list()

# make the interface readable
def choose_interface():
    if get_windows_if_list:
        win_iface = get_windows_if_list()
        for i, it in enumerate(win_iface, start=1):
            desc = it.get("description") or "<no-desc>"
            npf = it.get("name") or it.get("guid") or "<npf>"
            ip = it.get("ip") or ""
            print(f"{i:2d} {desc[:40]:40} {ip:15} -> {npf}")
        choice = input("choice interface by name (or press enter for default): ").strip()
        if not choice:
            return None
        try:
            idx = int(choice) - 1
            return win_iface[idx].get("name")
        except Exception:
            print("invalid choice")
            return None
    
    # fallback
    npfs = get_if_list()
    sys_if_addrs = psutil.net_if_addrs()
    print("npf adapters (pick index): ")
    for i, n in enumerate(npfs, start=1):
        print(f"{i:2d} {n}")
    print("\nsystem interfaces (name + ipv4): ")
    for name, addrs in sys_if_addrs.items():
        ips = [a.address for a in addrs if a.family == socket.AF_INET]
        ipstr = ", ".join(ips) if ips else "<no-ipv4>"
        print(f" {name:20} -> {ipstr}")
    choice = input("enter npf index (or enter to use default): ")
    if not choice:
        return None
    try:
        return npfs[int(choice) - 1]
    except Exception:
        print("invalid choice")
        return None
    
# make text ascii only to viewable and prevent random sym,bols
def safe_text_preview(raw_bytes, maxlen=80):
    try:
        txt = raw_bytes[:maxlen].decode("utf-8", errors="replace")
    except Exception:
        txt = str(raw_bytes[:maxlen])
    
    non_print = sum(1 for c in txt if ord(c) < 32 and c not in ("\n", "\r", "\t"))
    if non_print > (len(txt) * 0.3):
        return raw_bytes[:maxlen].hex() + ("..." if len(raw_bytes) > maxlen else "")
    return txt.replace("\n", "\\n").replace("\r", "\\r")

# single line summary
def summarize(packet):
    ts = format_time(packet.time) if hasattr(packet, "time") else ""

    if IP in packet:
        ip = packet[IP]
        src, dst = ip.src, ip.dst
    elif IPv6 in packet:
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
    else:
        return f"{ts} non-ip {packet.summary()}"
    
    proto = "TCP" if TCP in packet else "UDP" if UDP in packet else str(ip.proto)    
    sport = dport = ""
    if TCP in packet or UDP in packet:
        l4 = packet[TCP] if TCP in packet else packet[UDP]
        sport = getattr(l4, "sport", "")
        dport = getattr(l4, "dport", "")
    
    payload_preview = ""
    if Raw in packet:
        raw = packet[Raw].load
        payload_preview = safe_text_preview(raw, maxlen=80)
        payload_preview = " | " + payload_preview

    ports = f" {sport} -> {dport}" if sport or dport else ""
    return f"{ts} {src} -> {dst} {proto}{ports}{payload_preview}"

# save as .pcap
def save_pcap(packets: Iterable, path: str):
    file_path = Path(path)
    packets_list = list(packets)
    wrpcap(str(file_path), packets_list)

def capture_packets(
        iface: Optional[str] = None,
        count: int = 100,
        bpf_filter: Optional[str] = None,
        store: bool = False,
        timeout: Optional[int] = None,
        packet_handler: Optional[Callable] = None
):
    
    if iface:
        conf.iface = iface
    
    scapy_count = 0 if (count is None or count == 0) else count
    try:
        packets = sniff(
            iface = iface,
            count = scapy_count,
            filter = bpf_filter,
            prn = packet_handler,
            store = store,
            timeout = timeout
        )
        if store:
            return packets
        return None
    except PermissionError as pe:
        raise PermissionError(
            "permission denied run as admin"
        ) from pe
    except Exception as e:
        traceback.print_exc()
        raise

def print_summary(packet):
    print(summarize(packet))

def start_sniffer():
    print("===== Packet Sniffer =====")
    iface = choose_interface()

    try:
        count_raw = input("packets to capture (0 = infinte) [default 100]: ")
        count = int(count_raw) if count_raw else 100
    except ValueError:
        count = 100
    
    bpf = input('bpf filter (like "tcp port 80") or press enter for none: ').strip() or None
    save = input("save to pcap file, enter path or press enter to skip: ").strip() or None

    store = bool(save)
    print(f"starting capture iface={iface or 'default'} count={count or 'infinite'} filter={bpf or 'none'}")
    try:
        packets = capture_packets(iface=iface, count=count if count != 0 else None, bpf_filter=bpf, store=store, packet_handler=print_summary if not store else None)
        if save and packets:
            save_pcap(packets, save)
            print(f"saved pcap to {save}")
    except KeyboardInterrupt:
        print("\n capture interrupted by user")
    except PermissionError as p:
        print(str(p))
    except Exception as e:
        print("error starting capture: " + str(e))
