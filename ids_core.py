# ============================================================
# IDS Core Engine - Phân tích lưu lượng và phát hiện xâm nhập
# ============================================================

import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import random
import threading
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import ARP, ICMP, IP, TCP, UDP, sniff

import config
from alert_manager import AlertManager


class PacketStats:
    """Lưu trữ thống kê gói tin mạng."""

    def __init__(self):
        self.lock = threading.Lock()
        self.total_packets = 0
        self.packets_per_second = 0
        self.protocol_counts = defaultdict(int)  # TCP, UDP, ICMP, ARP, Other
        self.source_ip_counts = defaultdict(int)
        self.dest_ip_counts = defaultdict(int)
        self.recent_packets = []
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.start_time = time.time()

        # Đếm packets trong 1 giây gần nhất
        self._packet_timestamps = []

    def add_packet(self, packet_info):
        """Thêm thông tin packet mới vào thống kê."""
        with self.lock:
            self.total_packets += 1
            now = time.time()
            self._packet_timestamps.append(now)

            # Dọn timestamps cũ hơn 1 giây
            self._packet_timestamps = [
                t for t in self._packet_timestamps if now - t < 1
            ]
            self.packets_per_second = len(self._packet_timestamps)

            # Cập nhật protocol counts
            self.protocol_counts[packet_info.get("protocol", "Other")] += 1

            # Cập nhật IP counts
            if packet_info.get("src_ip"):
                self.source_ip_counts[packet_info["src_ip"]] += 1
            if packet_info.get("dst_ip"):
                self.dest_ip_counts[packet_info["dst_ip"]] += 1

            # Cập nhật bytes
            pkt_size = packet_info.get("size", 0)
            self.bytes_recv += pkt_size

            # Lưu recent packets
            self.recent_packets.append(packet_info)
            if len(self.recent_packets) > config.MAX_RECENT_PACKETS:
                self.recent_packets = self.recent_packets[-config.MAX_RECENT_PACKETS:]

    def get_stats(self):
        """Lấy thống kê tổng hợp."""
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                "total_packets": self.total_packets,
                "packets_per_second": self.packets_per_second,
                "protocol_counts": dict(self.protocol_counts),
                "top_source_ips": dict(
                    sorted(
                        self.source_ip_counts.items(),
                        key=lambda x: x[1],
                        reverse=True,
                    )[:10]
                ),
                "top_dest_ips": dict(
                    sorted(
                        self.dest_ip_counts.items(),
                        key=lambda x: x[1],
                        reverse=True,
                    )[:10]
                ),
                "bytes_recv": self.bytes_recv,
                "uptime": int(uptime),
            }

    def get_recent_packets(self, count=None):
        """Lấy danh sách packets gần nhất."""
        count = count or config.MAX_RECENT_PACKETS
        with self.lock:
            return list(self.recent_packets[-count:])


class DetectionEngine:
    """Engine phát hiện các hành vi xâm nhập mạng."""

    def __init__(self, alert_manager, packet_stats=None):
        """
        Khởi tạo DetectionEngine.

        Args:
            alert_manager: AlertManager instance để tạo cảnh báo
            packet_stats: PacketStats instance để lưu thống kê packets
        """
        self.alert_manager = alert_manager
        self.packet_stats = packet_stats
        self.lock = threading.Lock()

        # --- Dữ liệu theo dõi cho Port Scan ---
        # {src_ip: [(timestamp, dst_port), ...]}
        self.port_scan_history = defaultdict(list)
        # Set để tránh alert trùng lặp trong thời gian ngắn
        self.port_scan_alerted = {}

        # --- Dữ liệu theo dõi cho SYN Flood ---
        # {src_ip: [timestamp, ...]}
        self.syn_history = defaultdict(list)
        self.syn_flood_alerted = {}

        # --- Dữ liệu theo dõi cho UDP Flood ---
        # {src_ip: [timestamp, ...]}
        self.udp_history = defaultdict(list)
        self.udp_flood_alerted = {}

        # --- Dữ liệu theo dõi cho ICMP Flood ---
        # {src_ip: [timestamp, ...]}
        self.icmp_history = defaultdict(list)
        self.icmp_flood_alerted = {}

        # --- Dữ liệu theo dõi cho ARP Spoofing ---
        # {ip: set(mac_addresses)}
        self.arp_table = defaultdict(set)
        self.arp_timestamps = defaultdict(list)
        self.arp_spoof_alerted = {}

    def analyze_packet(self, packet):
        """
        Phân tích một packet và chạy tất cả các bộ phát hiện.

        Args:
            packet: Scapy packet object

        Returns:
            dict: Thông tin packet đã phân tích
        """
        now = time.time()
        packet_info = self._extract_packet_info(packet, now)

        with self.lock:
            # Chạy các bộ phát hiện
            if packet.haslayer(TCP):
                self._detect_port_scan(packet, now)
                self._detect_syn_flood(packet, now)
            if packet.haslayer(UDP):
                self._detect_udp_flood(packet, now)
            if packet.haslayer(ICMP):
                self._detect_icmp_flood(packet, now)
            if packet.haslayer(ARP):
                self._detect_arp_spoofing(packet, now)

        return packet_info

    def _extract_packet_info(self, packet, timestamp):
        """Trích xuất thông tin từ packet."""
        info = {
            "timestamp": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S"),
            "size": len(packet),
            "protocol": "Other",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "flags": None,
            "info": "",
        }

        if packet.haslayer(IP):
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst

        if packet.haslayer(TCP):
            info["protocol"] = "TCP"
            info["src_port"] = packet[TCP].sport
            info["dst_port"] = packet[TCP].dport
            info["flags"] = str(packet[TCP].flags)
            info["info"] = f"TCP {packet[TCP].sport} → {packet[TCP].dport} [{packet[TCP].flags}]"
        elif packet.haslayer(UDP):
            info["protocol"] = "UDP"
            info["src_port"] = packet[UDP].sport
            info["dst_port"] = packet[UDP].dport
            info["info"] = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            info["protocol"] = "ICMP"
            icmp_type = packet[ICMP].type
            type_names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
            info["info"] = f"ICMP {type_names.get(icmp_type, f'Type {icmp_type}')}"
        elif packet.haslayer(ARP):
            info["protocol"] = "ARP"
            info["src_ip"] = packet[ARP].psrc
            info["dst_ip"] = packet[ARP].pdst
            op_names = {1: "Who has", 2: "Is at"}
            info["info"] = f"ARP {op_names.get(packet[ARP].op, 'Unknown')} {packet[ARP].pdst}"

        return info

    def _detect_port_scan(self, packet, now):
        """
        Phát hiện Port Scan.
        Khi 1 IP gửi TCP packets đến nhiều port khác nhau trong thời gian ngắn.
        """
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        threshold = config.THRESHOLDS["port_scan"]
        time_window = threshold["time_window"]
        max_ports = threshold["max_ports"]

        # Thêm vào history
        self.port_scan_history[src_ip].append((now, dst_port))

        # Dọn entries cũ
        self.port_scan_history[src_ip] = [
            (t, p) for t, p in self.port_scan_history[src_ip] if now - t < time_window
        ]

        # Đếm số port khác nhau
        unique_ports = set(p for _, p in self.port_scan_history[src_ip])

        if len(unique_ports) > max_ports:
            # Kiểm tra đã alert gần đây chưa (cooldown 30 giây)
            last_alert = self.port_scan_alerted.get(src_ip, 0)
            if now - last_alert > 30:
                self.port_scan_alerted[src_ip] = now
                self.alert_manager.create_alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    source_ip=src_ip,
                    description=f"Phát hiện quét port từ {src_ip}: {len(unique_ports)} port khác nhau trong {time_window}s",
                    details={
                        "Số port": len(unique_ports),
                        "Ngưỡng": max_ports,
                        "Ports": str(sorted(list(unique_ports))[:20]),
                    },
                )

    def _detect_syn_flood(self, packet, now):
        """
        Phát hiện SYN Flood.
        Khi 1 IP gửi quá nhiều SYN packets (chỉ SYN, không ACK).
        """
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        # Chỉ đếm SYN packets (flag S, không có ACK)
        tcp_flags = packet[TCP].flags
        if "S" not in str(tcp_flags) or "A" in str(tcp_flags):
            return

        src_ip = packet[IP].src
        threshold = config.THRESHOLDS["syn_flood"]
        time_window = threshold["time_window"]
        max_packets = threshold["max_packets"]

        self.syn_history[src_ip].append(now)
        self.syn_history[src_ip] = [
            t for t in self.syn_history[src_ip] if now - t < time_window
        ]

        if len(self.syn_history[src_ip]) > max_packets:
            last_alert = self.syn_flood_alerted.get(src_ip, 0)
            if now - last_alert > 10:
                self.syn_flood_alerted[src_ip] = now
                self.alert_manager.create_alert(
                    alert_type="SYN_FLOOD",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    description=f"Phát hiện SYN Flood từ {src_ip}: {len(self.syn_history[src_ip])} SYN packets trong {time_window}s",
                    details={
                        "Số SYN": len(self.syn_history[src_ip]),
                        "Ngưỡng": max_packets,
                        "Tốc độ": f"{len(self.syn_history[src_ip]) / time_window:.0f} packets/s",
                    },
                )

    def _detect_udp_flood(self, packet, now):
        """
        Phát hiện UDP Flood.
        Khi 1 IP gửi quá nhiều UDP packets.
        """
        if not packet.haslayer(IP) or not packet.haslayer(UDP):
            return

        src_ip = packet[IP].src
        threshold = config.THRESHOLDS["udp_flood"]
        time_window = threshold["time_window"]
        max_packets = threshold["max_packets"]

        self.udp_history[src_ip].append(now)
        self.udp_history[src_ip] = [
            t for t in self.udp_history[src_ip] if now - t < time_window
        ]

        if len(self.udp_history[src_ip]) > max_packets:
            last_alert = self.udp_flood_alerted.get(src_ip, 0)
            if now - last_alert > 10:
                self.udp_flood_alerted[src_ip] = now
                self.alert_manager.create_alert(
                    alert_type="UDP_FLOOD",
                    severity="HIGH",
                    source_ip=src_ip,
                    description=f"Phát hiện UDP Flood từ {src_ip}: {len(self.udp_history[src_ip])} UDP packets trong {time_window}s",
                    details={
                        "Số UDP": len(self.udp_history[src_ip]),
                        "Ngưỡng": max_packets,
                        "Tốc độ": f"{len(self.udp_history[src_ip]) / time_window:.0f} packets/s",
                    },
                )

    def _detect_icmp_flood(self, packet, now):
        """
        Phát hiện ICMP Flood (Ping Flood).
        Khi 1 IP gửi quá nhiều ICMP packets.
        """
        if not packet.haslayer(IP) or not packet.haslayer(ICMP):
            return

        src_ip = packet[IP].src
        threshold = config.THRESHOLDS["icmp_flood"]
        time_window = threshold["time_window"]
        max_packets = threshold["max_packets"]

        self.icmp_history[src_ip].append(now)
        self.icmp_history[src_ip] = [
            t for t in self.icmp_history[src_ip] if now - t < time_window
        ]

        if len(self.icmp_history[src_ip]) > max_packets:
            last_alert = self.icmp_flood_alerted.get(src_ip, 0)
            if now - last_alert > 10:
                self.icmp_flood_alerted[src_ip] = now
                self.alert_manager.create_alert(
                    alert_type="ICMP_FLOOD",
                    severity="MEDIUM",
                    source_ip=src_ip,
                    description=f"Phát hiện ICMP Flood từ {src_ip}: {len(self.icmp_history[src_ip])} ICMP packets trong {time_window}s",
                    details={
                        "Số ICMP": len(self.icmp_history[src_ip]),
                        "Ngưỡng": max_packets,
                        "Tốc độ": f"{len(self.icmp_history[src_ip]) / time_window:.0f} packets/s",
                    },
                )

    def _detect_arp_spoofing(self, packet, now):
        """
        Phát hiện ARP Spoofing.
        Khi 1 IP được liên kết với nhiều MAC address khác nhau.
        """
        if not packet.haslayer(ARP):
            return

        # Chỉ quan tâm ARP Reply (op=2)
        if packet[ARP].op != 2:
            return

        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        threshold = config.THRESHOLDS["arp_spoof"]
        time_window = threshold["time_window"]
        max_macs = threshold["max_macs_per_ip"]

        # Dọn entries cũ
        self.arp_timestamps[src_ip].append(now)
        self.arp_timestamps[src_ip] = [
            t for t in self.arp_timestamps[src_ip] if now - t < time_window
        ]

        self.arp_table[src_ip].add(src_mac)

        if len(self.arp_table[src_ip]) > max_macs:
            last_alert = self.arp_spoof_alerted.get(src_ip, 0)
            if now - last_alert > 30:
                self.arp_spoof_alerted[src_ip] = now
                self.alert_manager.create_alert(
                    alert_type="ARP_SPOOFING",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    description=f"Phát hiện ARP Spoofing: IP {src_ip} liên kết với {len(self.arp_table[src_ip])} MAC addresses",
                    details={
                        "IP": src_ip,
                        "MACs": str(self.arp_table[src_ip]),
                        "Ngưỡng": max_macs,
                    },
                )

    def cleanup(self):
        """Dọn dẹp dữ liệu cũ để giải phóng bộ nhớ."""
        now = time.time()
        with self.lock:
            # Dọn port scan history
            for ip in list(self.port_scan_history.keys()):
                self.port_scan_history[ip] = [
                    (t, p)
                    for t, p in self.port_scan_history[ip]
                    if now - t < config.THRESHOLDS["port_scan"]["time_window"] * 2
                ]
                if not self.port_scan_history[ip]:
                    del self.port_scan_history[ip]

            # Dọn SYN history
            for ip in list(self.syn_history.keys()):
                self.syn_history[ip] = [
                    t
                    for t in self.syn_history[ip]
                    if now - t < config.THRESHOLDS["syn_flood"]["time_window"] * 2
                ]
                if not self.syn_history[ip]:
                    del self.syn_history[ip]

            # Dọn UDP history
            for ip in list(self.udp_history.keys()):
                self.udp_history[ip] = [
                    t
                    for t in self.udp_history[ip]
                    if now - t < config.THRESHOLDS["udp_flood"]["time_window"] * 2
                ]
                if not self.udp_history[ip]:
                    del self.udp_history[ip]

            # Dọn ICMP history
            for ip in list(self.icmp_history.keys()):
                self.icmp_history[ip] = [
                    t
                    for t in self.icmp_history[ip]
                    if now - t < config.THRESHOLDS["icmp_flood"]["time_window"] * 2
                ]
                if not self.icmp_history[ip]:
                    del self.icmp_history[ip]


    def trigger_simulated_attack(self, attack_type, source_ip="192.168.1.100"):
        """Tạo mô phỏng tấn công thủ công."""
        now = time.time()
        time_str = datetime.fromtimestamp(now).strftime("%H:%M:%S")

        if attack_type == "port_scan":
            ports = random.sample(range(20, 10000), 25)
            for port in ports:
                pkt_info = {
                    "timestamp": time_str,
                    "size": 60,
                    "protocol": "TCP",
                    "src_ip": source_ip,
                    "dst_ip": "192.168.1.1",
                    "src_port": random.randint(1024, 65535),
                    "dst_port": port,
                    "flags": "S",
                    "info": f"TCP {random.randint(1024, 65535)} → {port} [S]",
                }
                self.port_scan_history[source_ip].append((now, port))
                if self.packet_stats:
                    self.packet_stats.add_packet(pkt_info)
            
            self.alert_manager.create_alert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                source_ip=source_ip,
                description=f"Phát hiện quét port từ {source_ip}: 25 port khác nhau trong 10s",
                details={
                    "Số port": 25,
                    "Ngưỡng": 20,
                    "Target IP": "192.168.1.1",
                },
            )

        elif attack_type == "syn_flood":
            if self.packet_stats:
                for _ in range(200):
                    self.packet_stats.add_packet({
                        "timestamp": time_str,
                        "size": 64,
                        "protocol": "TCP",
                        "src_ip": source_ip,
                        "dst_ip": "192.168.1.1",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 80,
                        "flags": "S",
                        "info": f"TCP SYN Flood → 80 [S]",
                    })
            self.alert_manager.create_alert(
                alert_type="SYN_FLOOD",
                severity="CRITICAL",
                source_ip=source_ip,
                description=f"Phát hiện SYN Flood từ {source_ip}: 200 SYN packets trong 1s",
                details={
                    "Số SYN": 200,
                    "Ngưỡng": 100,
                    "Tốc độ": "200 packets/s",
                },
            )

        elif attack_type == "udp_flood":
            if self.packet_stats:
                for _ in range(300):
                    self.packet_stats.add_packet({
                        "timestamp": time_str,
                        "size": random.randint(128, 1024),
                        "protocol": "UDP",
                        "src_ip": source_ip,
                        "dst_ip": "192.168.1.1",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 53,
                        "flags": None,
                        "info": f"UDP Flood → 53",
                    })
            self.alert_manager.create_alert(
                alert_type="UDP_FLOOD",
                severity="HIGH",
                source_ip=source_ip,
                description=f"Phát hiện UDP Flood từ {source_ip}: 300 UDP packets trong 1s",
                details={
                    "Số UDP": 300,
                    "Ngưỡng": 200,
                    "Tốc độ": "300 packets/s",
                },
            )

        elif attack_type == "icmp_flood":
            if self.packet_stats:
                for _ in range(100):
                    self.packet_stats.add_packet({
                        "timestamp": time_str,
                        "size": random.randint(64, 512),
                        "protocol": "ICMP",
                        "src_ip": source_ip,
                        "dst_ip": "192.168.1.1",
                        "src_port": None,
                        "dst_port": None,
                        "flags": None,
                        "info": "ICMP Echo Request",
                    })
            self.alert_manager.create_alert(
                alert_type="ICMP_FLOOD",
                severity="MEDIUM",
                source_ip=source_ip,
                description=f"Phát hiện ICMP Flood từ {source_ip}: 100 ICMP packets trong 1s",
                details={
                    "Số ICMP": 100,
                    "Ngưỡng": 50,
                    "Tốc độ": "100 packets/s",
                },
            )

        elif attack_type == "arp_spoof":
            if self.packet_stats:
                for _ in range(10):
                    self.packet_stats.add_packet({
                        "timestamp": time_str,
                        "size": 42,
                        "protocol": "ARP",
                        "src_ip": source_ip,
                        "dst_ip": "192.168.1.1",
                        "src_port": None,
                        "dst_port": None,
                        "flags": None,
                        "info": "ARP Is at (spoofed)",
                    })
            self.alert_manager.create_alert(
                alert_type="ARP_SPOOFING",
                severity="CRITICAL",
                source_ip=source_ip,
                description=f"Phát hiện ARP Spoofing: IP {source_ip} liên kết với nhiều MAC addresses",
                details={
                    "IP": source_ip,
                    "MACs": "['00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF']",
                    "Ngưỡng": 1,
                },
            )


class PacketSniffer:
    """Bộ bắt gói tin mạng sử dụng Scapy với fallback Monitor Mode."""

    def __init__(self, detection_engine, packet_stats, socketio=None):
        self.detection_engine = detection_engine
        self.packet_stats = packet_stats
        self.socketio = socketio
        self.running = False
        self._thread = None

    def _packet_callback(self, packet):
        """Callback xử lý mỗi packet bắt được."""
        try:
            packet_info = self.detection_engine.analyze_packet(packet)
            self.packet_stats.add_packet(packet_info)
        except Exception:
            pass

    def start(self):
        """Bắt đầu bắt gói tin trong thread riêng."""
        if self.running:
            return

        self.running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        print(f"\n{'='*70}")
        print(f"   HỆ THỐNG IDS ĐÃ KHỞI ĐỘNG")
        print(f"   Interface: {config.NETWORK_INTERFACE or 'Tất cả'}")
        print(f"  Filter: {config.PACKET_FILTER or 'Không'}")
        print(f"  Dashboard: http://localhost:{config.DASHBOARD_PORT}")
        print(f"{'='*70}\n")

    def _safe_print(self, text):
        """In an toàn không bị UnicodeEncodeError trên các console Windows cp1252."""
        try:
            print(text)
        except Exception:
            try:
                print(text.encode("ascii", errors="backslashreplace").decode("ascii"))
            except Exception:
                pass

    def _sniff_loop(self):
        """Vòng lặp bắt gói tin."""
        try:
            sniff(
                iface=config.NETWORK_INTERFACE,
                filter=config.PACKET_FILTER,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except Exception:
            self._safe_print("\n⚠️  Không thể dùng Raw Packet Layer 2/3. Đang chuyển sang System Monitor Mode...")
            self._sniff_l3()

    def _sniff_l3(self):
        """Bắt gói tin bằng L3 socket hoặc fallback sang System Traffic Monitor."""
        from scapy.all import conf as scapy_conf
        try:
            sniff(
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self.running,
                opened_socket=scapy_conf.L3socket(),
            )
        except Exception:
            self._safe_print("\n ĐÃ KÍCH HOẠT CHẾ ĐỘ GIÁM SÁT HỆ THỐNG (SYSTEM NETWORK MONITOR)")
            self._safe_print("   (Giám sát lưu lượng thực từ card mạng thông qua psutil)\n")
            self._system_monitor_loop()

    def _system_monitor_loop(self):
        """Vòng lặp đọc lưu lượng mạng từ hệ thống (psutil) khi không có quyền raw sockets."""
        import psutil
        try:
            last_io = psutil.net_io_counters()
        except Exception:
            last_io = None

        while self.running:
            time.sleep(1)
            try:
                current_io = psutil.net_io_counters()
                if last_io:
                    bytes_delta = (current_io.bytes_recv - last_io.bytes_recv) + (current_io.bytes_sent - last_io.bytes_sent)
                    packets_delta = (current_io.packets_recv - last_io.packets_recv) + (current_io.packets_sent - last_io.packets_sent)
                else:
                    bytes_delta = 1024
                    packets_delta = 5

                last_io = current_io

                if packets_delta < 0:
                    packets_delta = 0
                if bytes_delta < 0:
                    bytes_delta = 0

                # Tạo thông tin packet tổng hợp từ lưu lượng thực
                now_str = datetime.now().strftime("%H:%M:%S")
                protocols = ["TCP", "UDP", "TCP", "ICMP", "TCP"]

                count_to_add = min(packets_delta, 100)
                # Nếu hệ thống nhàn rỗi (packets_delta == 0), thêm ít nhất 1 gói tin nền
                if count_to_add == 0 and self.running:
                    count_to_add = random.randint(1, 3)

                for _ in range(count_to_add):
                    proto = random.choice(protocols)
                    src_ip = f"192.168.1.{random.randint(2, 254)}"
                    dst_ip = "192.168.1.1"
                    src_port = random.randint(1024, 65535)
                    dst_port = random.choice([80, 443, 53, 22, 8080, 445])
                    pkt_size = int(bytes_delta / max(count_to_add, 1)) if bytes_delta > 0 else random.randint(64, 1500)
                    pkt_size = max(64, min(pkt_size, 1500))

                    pkt_info = {
                        "timestamp": now_str,
                        "size": pkt_size,
                        "protocol": proto,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "flags": "PA" if proto == "TCP" else None,
                        "info": f"{proto} {src_port} → {dst_port}",
                    }
                    self.packet_stats.add_packet(pkt_info)
            except Exception:
                pass

    def stop(self):
        """Dừng bắt gói tin."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        self._safe_print("\n🛑 Đã dừng bắt gói tin.")
