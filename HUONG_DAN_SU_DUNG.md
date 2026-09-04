# 🛡️ HƯỚNG DẪN SỬ DỤNG VÀ GIẢI THÍCH HỆ THỐNG IDS (PBL4)

> **Dự án**: Hệ thống phát hiện xâm nhập mạng (Intrusion Detection System - IDS) cơ bản  
> **Học phần**: PBL4 - Dự án Công nghệ Thông tin  
> **Công nghệ chính**: Python 3.10+ | Scapy | Flask | Flask-SocketIO | Chart.js | HTML5/CSS3  

---

## 📖 MỤC LỤC
1. [Giới thiệu Đề tài](#1-giới-thiệu-đề-tài)
2. [Cơ chế & Nguyên lý Hoạt động Kỹ thuật](#2-cơ-chế--nguyên-lý-hoạt-động-kỹ-thuật)
3. [Cách Hệ thống Trích xuất Địa chỉ IP & Thông số](#3-cách-hệ-thống-trích-xuất-địa-chỉ-ip--thông-số)
4. [Mô tả Chi tiết Các Chức năng Hệ thống](#4-mô-tả-chi-tiết-các-chức-năng-hệ-thống)
5. [Cấu trúc Thư mục Dự án](#5-cấu-trúc-thư-mục-dự-án)
6. [Hướng dẫn Chạy và Kiểm thử Dự án](#6-hướng-dẫn-chạy-và-kiểm-thử-dự-án)
7. [Cách Dừng và Tắt Chương trình](#7-cách-dừng-và-tắt-chương-trình)
8. [Xử lý Sự cố Thường gặp (Troubleshooting)](#8-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## 1. GIỚI THIỆU ĐỀ TÀI

Hệ thống **IDS (Intrusion Detection System)** là ứng dụng giám sát an ninh mạng real-time, liên tục lắng nghe lưu lượng gói tin (packets) trên mạng, phân tích dấu hiệu bất thường và đưa ra cảnh báo kịp thời nhằm phát hiện các hành vi tấn công phổ biến như:
- **Port Scan** (Quét cổng dịch vụ)
- **SYN Flood** (Tấn công từ chối dịch vụ TCP)
- **UDP Flood** (Tấn công ngập lụt UDP)
- **ICMP Flood** (Tấn công Ping Flood)
- **ARP Spoofing** (Giả mạo địa chỉ ARP trong mạng LAN)

Ứng dụng cung cấp **Web Dashboard** trực quan hóa số liệu mạng theo thời gian thực (real-time) với biểu đồ và bảng cảnh báo chi tiết.

---

## 2. CƠ CHẾ & NGUYÊN LÝ HOẠT ĐỘNG KỸ THUẬT

Hệ thống hoạt động theo mô hình **4 Tầng Kiến trúc**:

- **Lớp Thu thập Gói tin (Packet Capture - `ids_core.py`)**: Sử dụng thư viện **Scapy** hoặc **psutil** đọc dữ liệu từ card mạng. Nếu không có quyền Administrator, hệ thống tự động chuyển sang chế độ Monitor đọc lưu lượng thực từ OS (`psutil.net_io_counters()`), đảm bảo Web Dashboard luôn nhảy số.
- **Lớp Phân tích & Thuật toán Phát hiện (`DetectionEngine`)**: Áp dụng các luật phát hiện:
  - 🔍 **Port Scan**: Kiểm tra nếu 1 IP nguồn gửi tới > 20 cổng khác nhau trong 10s.
  - 🌊 **SYN Flood**: Đếm số cờ TCP SYN từ 1 IP trong 1s (> 100 packets/s $\rightarrow$ Báo động Critical).
  - 🌊 **UDP Flood**: Đếm số gói UDP từ 1 IP trong 1s (> 200 packets/s $\rightarrow$ Báo động High).
  - 🏓 **ICMP Flood**: Đếm số gói Ping trong 1s (> 50 packets/s $\rightarrow$ Báo động Medium).
  - 🎭 **ARP Spoofing**: Theo dõi bảng ánh xạ giữa IP và MAC address trong mạng LAN.
- **Lớp Quản lý Cảnh báo (`alert_manager.py`)**: Gom thông tin thành đối tượng `Alert`, ghi log file `alerts.log`, in ra Console màu và đẩy dữ liệu lên Web qua **WebSocket (Socket.IO)**.
- **Lớp Web Dashboard (`app.py` - Flask + Socket.IO)**: Truyền dữ liệu tới giao diện HTML/JS real-time.

---

## 3. CÁCH HỆ THỐNG TRÍCH XUẤT ĐỊA CHỈ IP & THÔNG SỐ

Khi các thiết bị giao tiếp trên mạng, dữ liệu được đóng gói theo mô hình **TCP/IP**:

```text
+-------------------------------------------------------+
|  Khung Ethernet (MAC Nguồn, MAC Đích)                 |  Lớp 2 (Data Link)
|  +-------------------------------------------------+  |
|  |  Gói tin IP (IP Nguồn, IP Đích)                 |  |  Lớp 3 (Network)
|  |  +-------------------------------------------+  |  |
|  |  |  Phân đoạn TCP/UDP (Port Nguồn, Port Đích)  |  |  |  Lớp 4 (Transport)
|  |  +-------------------------------------------+  |  |
|  +-------------------------------------------------+  |
+-------------------------------------------------------+
```

Scapy can thiệp vào tầng Network (Lớp 3) để đọc các Tiêu đề (Header) của gói tin:

```python
# Đoạn mã trích xuất thông số từ gói tin trong ids_core.py:
if packet.haslayer(IP):
    src_ip = packet[IP].src   # Địa chỉ IP Máy gửi (Source IP)
    dst_ip = packet[IP].dst   # Địa chỉ IP Máy nhận (Destination IP)

if packet.haslayer(TCP):
    src_port = packet[TCP].sport  # Port máy gửi
    dst_port = packet[TCP].dport  # Port dịch vụ đích
    flags = str(packet[TCP].flags) # Cờ TCP (SYN, ACK, FIN, RST...)
```

---

## 4. MÔ TẢ CHI TIẾT CÁC CHỨC NĂNG HỆ THỐNG

| STT | Chức năng | Mô tả chi tiết |
|---|---|---|
| 1 | **Giám sát Lưu lượng Real-time** | Hiển thị Tổng số gói tin, Tốc độ (Packets/giây), Dung lượng dữ liệu nhận (B, KB, MB) và Uptime hệ thống. |
| 2 | **Bắt đầu / Dừng Sniffer** | Nút điều khiển `▶ Bắt đầu` và `⏹ Dừng` trên Web cho phép bật/tắt quá trình thu thập gói tin trực tiếp từ giao diện. |
| 3 | **Biểu đồ Lưu lượng Mạng** | Biểu đồ đường (Line Chart) cập nhật độ biến động của lưu lượng mạng theo từng giây. |
| 4 | **Phân bố Giao thức** | Biểu đồ tròn (Doughnut Chart) thống kê tỷ lệ % giữa các giao thức `TCP`, `UDP`, `ICMP`, `ARP`. |
| 5 | **Thống kê Top IP & Loại Cảnh báo** | Biểu đồ cột thể hiện các IP nguồn phát lưu lượng lớn nhất và thống kê phân loại các cuộc tấn công. |
| 6 | **Bảng Cảnh báo Mở rộng (Expandable Alerts)** | Danh sách cuộc tấn công phát hiện được sắp xếp theo thời gian. Người dùng có thể click vào từng dòng để mở xem chi tiết các thông số kỹ thuật. |
| 7 | **Thông báo Toast Popup** | Hiển thị ô thông báo trượt góc màn hình mỗi khi phát hiện một cuộc tấn công mới. |
| 8 | **Ghi Log & Gửi Email Cảnh báo** | Tự động ghi lại các sự kiện bất thường vào file `alerts.log` và gửi Email qua SMTP khi có cảnh báo nghiêm trọng (`HIGH`/`CRITICAL`). |
| 9 | **Kiểm thử Tấn công (`test_attack.py`)** | Công cụ mô phỏng tấn công gửi gói tin giả lập để kiểm tra khả năng phát hiện của IDS. |

---

## 5. CẤU TRÚC THƯ MỤC DỰ ÁN

```text
PBL4/
├── app.py                  # Server Flask & các API Endpoints
├── ids_core.py             # Bộ lắng nghe (PacketSniffer) & Engine phát hiện (DetectionEngine)
├── alert_manager.py        # Quản lý phát cảnh báo (Console, Log, WebSocket, Email)
├── config.py               # File cấu hình (Ngưỡng phát hiện, Cổng Dashboard, Email SMTP)
├── test_attack.py          # Script công cụ mô phỏng tấn công để kiểm thử
├── requirements.txt        # Danh sách thư viện Python cần thiết
├── HUONG_DAN_SU_DUNG.md    # Tài liệu hướng dẫn sử dụng và báo cáo đồ án
├── alerts.log              # File nhật ký lưu trữ các cảnh báo (Tự động sinh ra)
├── templates/
│   └── dashboard.html      # Giao diện Web Dashboard HTML5
└── static/
    ├── css/
    │   └── style.css       # CSS Dark Theme Glassmorphism
    └── js/
        └── dashboard.js    # Xử lý Logic Real-time (Socket.IO + REST Polling + Chart.js)
```

---

## 6. HƯỚNG DẪN CHẠY VÀ KIỂM THỬ DỰ ÁN

### Bước 1: Khởi chạy Server IDS
Mở **Command Prompt (CMD)** hoặc **PowerShell** tại thư mục `d:\PBL4\PBL4` và chạy:

```cmd
.venv\Scripts\python.exe app.py
```
*(Nếu muốn bắt trực tiếp gói tin thô trên card mạng thật, hãy mở CMD bằng quyền **Run as Administrator**).*

---

### Bước 2: Truy cập Web Dashboard
Mở trình duyệt web bất kỳ (Chrome, Edge, Firefox) và truy cập địa chỉ:
👉 **`http://localhost:5000`**

*(Mẹo: Nhấn `Ctrl + F5` để làm mới bộ nhớ đệm trình duyệt khi mở lần đầu).*

---

### Bước 3: Chạy Mô phỏng Tấn công để Kiểm thử
Mở **thêm 1 cửa sổ Terminal mới** tại thư mục `d:\PBL4\PBL4` và thực hiện lệnh:

```cmd
# Chạy tất cả các loại tấn công mô phỏng (Port Scan, SYN Flood, UDP Flood, ICMP Flood)
.venv\Scripts\python.exe test_attack.py all 127.0.0.1
```

Hoặc chạy từng loại tấn công riêng lẻ:
```cmd
.venv\Scripts\python.exe test_attack.py port_scan 127.0.0.1
.venv\Scripts\python.exe test_attack.py syn_flood 127.0.0.1
.venv\Scripts\python.exe test_attack.py udp_flood 127.0.0.1
.venv\Scripts\python.exe test_attack.py icmp_flood 127.0.0.1
```

Quan sát giao diện Dashboard tại `http://localhost:5000`: Số gói tin nhảy liên tục, các biểu đồ biến động và thông báo cảnh báo đỏ/vàng lập tức nổ ra trên bảng Cảnh báo.

---

## 7. CÁCH DỪNG VÀ TẮT CHƯƠNG TRÌNH

### Cách 1: Tắt tại Terminal (Khuyên dùng)
Nhấp chuột vào cửa sổ Terminal đang chạy `app.py` và nhấn tổ hợp phím:
👉 **`Ctrl` + `C`**

### Cách 2: Tắt cưỡng chế bằng lệnh (Khi chương trình chạy ngầm)
Nếu lỡ đóng cửa sổ Terminal mà server vẫn chạy chiếm cổng 5000, mở CMD gõ:

```cmd
taskkill /F /IM python.exe /T
```

---

## 8. XỬ LÝ SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

| Hiện tượng | Nguyên nhân | Cách khắc phục |
|---|---|---|
| Báo lỗi `No module named ...` | Chưa kích hoạt môi trường `.venv` | Sử dụng đường dẫn `.venv\Scripts\python.exe` khi chạy lệnh. |
| Dashboard báo `Mất kết nối` hoặc số `0` | Server chưa chạy hoặc trình duyệt nhớ cache | Kiểm tra đã chạy `python app.py` chưa và nhấn `Ctrl + F5` trên trình duyệt. |
| Cảnh báo `winpcap is not installed` | Thiếu driver Npcap trên Windows | Hệ thống sẽ **tự động kích hoạt Chế độ Monitor**, bạn vẫn test và xem Dashboard bình thường. Nếu muốn bắt gói tin thật, hãy tải và cài [Npcap](https://npcap.com/#download). |
| Lỗi font chữ ngoằn ngoèo trên Windows CMD | CMD mặc định không dùng UTF-8 | Hệ thống đã tích hợp mã tự động sửa encoding `sys.stdout.reconfigure(encoding="utf-8")`. |
