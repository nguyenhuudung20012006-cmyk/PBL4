# ============================================================
# IDS Configuration - Cấu hình Hệ thống Phát hiện Xâm nhập
# ============================================================

import os

# -----------------------------------------------------------
# Network Interface Configuration
# -----------------------------------------------------------
# None = lắng nghe trên tất cả interfaces
# Trên Windows, có thể chỉ định tên interface cụ thể
NETWORK_INTERFACE = None

# -----------------------------------------------------------
# Detection Thresholds - Ngưỡng phát hiện
# -----------------------------------------------------------
THRESHOLDS = {
    # Port Scan: Số port khác nhau từ 1 IP trong TIME_WINDOW giây
    "port_scan": {
        "max_ports": 20,
        "time_window": 10,  # giây
    },
    # SYN Flood: Số SYN packets từ 1 IP trong TIME_WINDOW giây
    "syn_flood": {
        "max_packets": 100,
        "time_window": 1,  # giây
    },
    # UDP Flood: Số UDP packets từ 1 IP trong TIME_WINDOW giây
    "udp_flood": {
        "max_packets": 200,
        "time_window": 1,  # giây
    },
    # ICMP Flood: Số ICMP packets từ 1 IP trong TIME_WINDOW giây
    "icmp_flood": {
        "max_packets": 50,
        "time_window": 1,  # giây
    },
    # ARP Spoofing: Số MAC addresses khác nhau cho 1 IP
    "arp_spoof": {
        "max_macs_per_ip": 1,
        "time_window": 30,  # giây
    },
}

# -----------------------------------------------------------
# Alert Configuration - Cấu hình cảnh báo
# -----------------------------------------------------------
# Mức cảnh báo
ALERT_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Mức cảnh báo tối thiểu để gửi email
EMAIL_ALERT_LEVEL = "HIGH"

# File log cảnh báo
ALERT_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.log")

# -----------------------------------------------------------
# Email Configuration (SMTP) - Cấu hình email
# -----------------------------------------------------------
EMAIL_ENABLED = False  # Đặt True nếu muốn gửi email cảnh báo
EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your_email@gmail.com",
    "sender_password": "your_app_password",  # Gmail App Password
    "receiver_email": "admin@example.com",
}

# -----------------------------------------------------------
# Web Dashboard Configuration
# -----------------------------------------------------------
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = False

# Số packet gần nhất hiển thị trên dashboard
MAX_RECENT_PACKETS = 50

# Số alert gần nhất hiển thị trên dashboard
MAX_RECENT_ALERTS = 100

# Tần suất cập nhật dashboard (giây)
DASHBOARD_UPDATE_INTERVAL = 1

# -----------------------------------------------------------
# Packet Capture Configuration
# -----------------------------------------------------------
# BPF filter cho Scapy sniff (None = bắt tất cả)
# Ví dụ: "tcp", "udp", "tcp port 80", "host 192.168.1.1"
PACKET_FILTER = None

# Số packet tối đa lưu trong bộ nhớ
MAX_PACKET_HISTORY = 10000
