# 🛡️ Hệ thống Phát hiện Xâm nhập Mạng (IDS) cơ bản

> 📖 **Xem tài liệu hướng dẫn và báo cáo đồ án chi tiết tại**: [`HUONG_DAN_SU_DUNG.md`](file:///d:/PBL4/PBL4/HUONG_DAN_SU_DUNG.md)

Hệ thống giám sát gói tin mạng real-time và cảnh báo khi phát hiện hành vi bất thường, sử dụng Python + Scapy với giao diện web dashboard trực quan.

## 📋 Tính năng

| Tính năng | Mô tả |
|---|---|
| **Bắt gói tin** | Sử dụng Scapy sniff real-time |
| **Phát hiện Port Scan** | Phát hiện khi 1 IP quét nhiều port |
| **Phát hiện SYN Flood** | Phát hiện tấn công SYN Flood |
| **Phát hiện UDP Flood** | Phát hiện tấn công UDP Flood |
| **Phát hiện ICMP Flood** | Phát hiện tấn công Ping Flood |
| **Phát hiện ARP Spoofing** | Phát hiện giả mạo ARP |
| **Cảnh báo Console** | In cảnh báo với màu sắc |
| **Cảnh báo Email** | Gửi email qua SMTP (tùy chọn) |
| **Log File** | Ghi log vào `alerts.log` |
| **Web Dashboard** | Giao diện trực quan real-time |

## 🚀 Cài đặt

### Yêu cầu hệ thống
- Python 3.10 trở lên
- **Npcap** (Windows) - [Tải tại đây](https://npcap.com/#download)
  - Khi cài đặt, chọn **"Install Npcap in WinPcap API-compatible Mode"**

### Bước 1: Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### Bước 2: Cài đặt Npcap (Windows)
1. Tải Npcap từ https://npcap.com/#download
2. Chạy installer với quyền Administrator
3. Chọn "Install Npcap in WinPcap API-compatible Mode"

## ⚙️ Cấu hình

Mở file `config.py` để tùy chỉnh:

### Ngưỡng phát hiện
```python
THRESHOLDS = {
    "port_scan": {"max_ports": 20, "time_window": 10},
    "syn_flood": {"max_packets": 100, "time_window": 1},
    "udp_flood": {"max_packets": 200, "time_window": 1},
    "icmp_flood": {"max_packets": 50, "time_window": 1},
    "arp_spoof": {"max_macs_per_ip": 1, "time_window": 30},
}
```

### Email (tùy chọn)
```python
EMAIL_ENABLED = True
EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your_email@gmail.com",
    "sender_password": "your_app_password",
    "receiver_email": "admin@example.com",
}
```

## 🏃 Chạy chương trình

### Bước 1: Khởi động IDS
**⚠️ Cần chạy với quyền Administrator** (để Scapy bắt được gói tin)

```bash
python app.py
```

### Bước 2: Mở Dashboard
Mở trình duyệt tại: http://localhost:5000

### Bước 3: Test với mô phỏng tấn công (tùy chọn)
Mở terminal mới (quyền Administrator):

```bash
# Chạy tất cả mô phỏng
python test_attack.py all 127.0.0.1

# Hoặc chạy từng loại
python test_attack.py port_scan 127.0.0.1
python test_attack.py syn_flood 127.0.0.1
python test_attack.py udp_flood 127.0.0.1
python test_attack.py icmp_flood 127.0.0.1
```

## 📁 Cấu trúc dự án

```
PBL4/
├── app.py                  # Flask application chính
├── ids_core.py             # Core IDS engine (sniffer + detection)
├── alert_manager.py        # Quản lý cảnh báo (console/email/log)
├── config.py               # File cấu hình
├── test_attack.py          # Script mô phỏng tấn công
├── requirements.txt        # Dependencies
├── README.md               # Hướng dẫn sử dụng
├── alerts.log              # File log cảnh báo (tự tạo)
├── templates/
│   └── dashboard.html      # Template giao diện dashboard
└── static/
    ├── css/
    │   └── style.css        # CSS dark theme
    └── js/
        └── dashboard.js     # JavaScript real-time
```

## 🛠️ Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | Python 3.10+ |
| Bắt gói tin | Scapy |
| Web framework | Flask + Flask-SocketIO |
| Real-time | WebSocket (Socket.IO) |
| Visualization | Chart.js |
| Email | smtplib (built-in) |

## ⚠️ Lưu ý quan trọng

- **Quyền Administrator**: Cả IDS và test script đều cần chạy với quyền Administrator
- **Npcap**: Bắt buộc phải cài Npcap trên Windows
- **Test script**: Chỉ sử dụng trên mạng riêng/localhost, KHÔNG dùng trên mạng production
- **Hiệu năng**: Hệ thống phù hợp cho mục đích học tập, không dùng cho production

## 📄 License

Dự án PBL4 - Mục đích học tập.
