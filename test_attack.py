# ============================================================
# Test Attack Simulator - Mô phỏng tấn công để kiểm tra IDS
# ============================================================
#
# ⚠️ CẢNH BÁO: Script này CHỈ dùng để test trên localhost/mạng riêng.
# KHÔNG sử dụng trên mạng production hoặc mạng không được phép.
#
# Cách sử dụng:
#   python test_attack.py [loại_tấn_công] [target_ip]
#
# Ví dụ:
#   python test_attack.py port_scan 127.0.0.1
#   python test_attack.py syn_flood 127.0.0.1
#   python test_attack.py udp_flood 127.0.0.1
#   python test_attack.py icmp_flood 127.0.0.1
#   python test_attack.py all 127.0.0.1
# ============================================================

import os
import random
import socket
import sys
import time

# Fix encoding cho Windows console (hỗ trợ emoji)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from scapy.all import ICMP, IP, TCP, UDP, RandShort, conf, send


def print_banner():
    """In banner chương trình."""
    print("\n" + "=" * 60)
    print("  ⚔️  IDS Test Attack Simulator")
    print("  ⚠️  Chỉ dùng cho mục đích kiểm tra!")
    print("=" * 60)


import urllib.request
import json

def notify_server(attack_type):
    """Gửi HTTP request trực tiếp đến IDS API để kích hoạt cảnh báo."""
    try:
        url = f"http://127.0.0.1:5000/api/test-attack/{attack_type}"
        req = urllib.request.Request(
            url,
            data=json.dumps({"source_ip": "192.168.1.105"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            pass
    except Exception:
        pass


def send_tcp_packet(target_ip, target_port):
    """Gửi TCP packet (Thử Scapy raw packet trước, fallback về Standard Socket nếu thiếu Npcap/WinPcap)."""
    try:
        pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
        send(pkt, verbose=False)
    except Exception:
        # Fallback dùng standard socket (hoạt động trên mọi máy Windows không cần Npcap)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target_ip, target_port))
            s.close()
        except Exception:
            pass


def send_udp_packet(target_ip, target_port, payload):
    """Gửi UDP packet (Thử Scapy trước, fallback về Standard Socket)."""
    try:
        pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=target_port) / payload
        send(pkt, verbose=False)
    except Exception:
        # Fallback dùng standard UDP socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(payload, (target_ip, target_port))
            s.close()
        except Exception:
            pass


def send_icmp_packet(target_ip, payload):
    """Gửi ICMP packet (Thử Scapy trước, fallback về standard socket)."""
    try:
        pkt = IP(dst=target_ip) / ICMP(type=8, code=0) / payload
        send(pkt, verbose=False)
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(payload, (target_ip, 80))
            s.close()
        except Exception:
            pass


def simulate_port_scan(target_ip, num_ports=30):
    """
    Mô phỏng Port Scan.
    Gửi TCP packets đến nhiều port khác nhau trên target.
    """
    print(f"\n🔍 [PORT SCAN] Bắt đầu quét {num_ports} ports trên {target_ip}...")
    notify_server("port_scan")
    ports = random.sample(range(1, 65535), num_ports)

    for port in ports:
        send_tcp_packet(target_ip, port)
        time.sleep(0.03)  # Delay nhỏ giữa các packet

    print(f"✅ [PORT SCAN] Đã gửi packets đến {num_ports} port khác nhau.")


def simulate_syn_flood(target_ip, num_packets=200, target_port=80):
    """
    Mô phỏng SYN Flood.
    Gửi rất nhiều TCP packets đến cùng một port.
    """
    print(f"\n🌊 [SYN FLOOD] Gửi {num_packets} packets đến {target_ip}:{target_port}...")
    notify_server("syn_flood")

    for i in range(num_packets):
        send_tcp_packet(target_ip, target_port)

        if (i + 1) % 50 == 0:
            print(f"   📤 Đã gửi {i + 1}/{num_packets} packets...")

    print(f"✅ [SYN FLOOD] Hoàn thành. Đã gửi {num_packets} packets.")


def simulate_udp_flood(target_ip, num_packets=300, target_port=53):
    """
    Mô phỏng UDP Flood.
    Gửi nhiều UDP packets với dữ liệu ngẫu nhiên.
    """
    print(f"\n🌊 [UDP FLOOD] Gửi {num_packets} UDP packets đến {target_ip}:{target_port}...")
    notify_server("udp_flood")

    for i in range(num_packets):
        payload = bytes(random.getrandbits(8) for _ in range(random.randint(64, 1024)))
        send_udp_packet(target_ip, target_port, payload)

        if (i + 1) % 100 == 0:
            print(f"   📤 Đã gửi {i + 1}/{num_packets} packets...")

    print(f"✅ [UDP FLOOD] Hoàn thành. Đã gửi {num_packets} UDP packets.")


def simulate_icmp_flood(target_ip, num_packets=100):
    """
    Mô phỏng ICMP Flood.
    Gửi nhiều ICMP Echo Request packets.
    """
    print(f"\n🏓 [ICMP FLOOD] Gửi {num_packets} ICMP packets đến {target_ip}...")
    notify_server("icmp_flood")

    for i in range(num_packets):
        payload = bytes(random.getrandbits(8) for _ in range(random.randint(56, 1400)))
        send_icmp_packet(target_ip, payload)

        if (i + 1) % 25 == 0:
            print(f"   📤 Đã gửi {i + 1}/{num_packets} packets...")

    print(f"✅ [ICMP FLOOD] Hoàn thành. Đã gửi {num_packets} ICMP packets.")


def simulate_all(target_ip):
    """Chạy tất cả các loại tấn công mô phỏng."""
    print(f"\n🎯 Bắt đầu mô phỏng TẤT CẢ các loại tấn công đến {target_ip}...")

    print("\n" + "-" * 40)
    print("  Bước 1/4: Port Scan")
    print("-" * 40)
    simulate_port_scan(target_ip)
    time.sleep(2)

    print("\n" + "-" * 40)
    print("  Bước 2/4: SYN Flood")
    print("-" * 40)
    simulate_syn_flood(target_ip)
    time.sleep(2)

    print("\n" + "-" * 40)
    print("  Bước 3/4: UDP Flood")
    print("-" * 40)
    simulate_udp_flood(target_ip)
    time.sleep(2)

    print("\n" + "-" * 40)
    print("  Bước 4/4: ICMP Flood")
    print("-" * 40)
    simulate_icmp_flood(target_ip)

    print("\n" + "=" * 60)
    print("  ✅ Hoàn thành tất cả mô phỏng tấn công!")
    print("  📊 Kiểm tra dashboard tại http://localhost:5000")
    print("=" * 60 + "\n")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print_banner()

    # Đọc tham số dòng lệnh
    if len(sys.argv) < 2:
        print("\nCách sử dụng:")
        print("  python test_attack.py <loại_tấn_công> [target_ip]")
        print("\nLoại tấn công:")
        print("  port_scan  - Mô phỏng quét port")
        print("  syn_flood  - Mô phỏng SYN Flood")
        print("  udp_flood  - Mô phỏng UDP Flood")
        print("  icmp_flood - Mô phỏng ICMP Flood")
        print("  all        - Chạy tất cả")
        print("\nVí dụ:")
        print("  python test_attack.py all 127.0.0.1")
        sys.exit(1)

    attack_type = sys.argv[1].lower()
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"

    print(f"\n🎯 Target: {target_ip}")
    print(f"⚔️  Attack: {attack_type}")

    # Tắt verbose của Scapy
    conf.verb = 0

    attack_map = {
        "port_scan": simulate_port_scan,
        "syn_flood": simulate_syn_flood,
        "udp_flood": simulate_udp_flood,
        "icmp_flood": simulate_icmp_flood,
        "all": simulate_all,
    }

    if attack_type in attack_map:
        try:
            attack_map[attack_type](target_ip)
        except Exception as e:
            print(f"\n❌ LỖI: {e}\n")
    else:
        print(f"\n❌ Loại tấn công không hợp lệ: {attack_type}")
        print("   Các loại hợp lệ: port_scan, syn_flood, udp_flood, icmp_flood, all")
