# 📖 Hướng Dẫn Sử Dụng - Hệ Thống Phát Hiện Xâm Nhập Mạng (IDS)

Tài liệu này cung cấp hướng dẫn chi tiết từng bước để cài đặt, cấu hình và chạy hệ thống IDS của dự án PBL4.

---

## 1. Yêu Cầu Hệ Thống

Trước khi bắt đầu, hãy đảm bảo máy tính của bạn đáp ứng các yêu cầu sau:
- **Hệ điều hành**: Windows (đã được test) hoặc Linux.
- **Python**: Phiên bản **3.10** trở lên.
- **Npcap (Dành riêng cho Windows)**: Thư viện cần thiết để thư viện `scapy` có thể bắt được gói tin mạng trên Windows.
  - Tải tại: [https://npcap.com/#download](https://npcap.com/#download)
  - **Lưu ý quan trọng khi cài đặt**: Phải tích chọn ô **"Install Npcap in WinPcap API-compatible Mode"** trong quá trình cài đặt Npcap.

---

## 2. Cài Đặt Môi Trường

### Bước 2.1: Mở Terminal / Command Prompt
Mở thư mục chứa mã nguồn của dự án (thư mục `PBL4`), nhấp chuột phải chọn `Open in Terminal` hoặc mở Command Prompt và dùng lệnh `cd` để di chuyển đến thư mục này.

### Bước 2.2: Tạo môi trường ảo (Khuyến nghị)
Để tránh xung đột thư viện với các project khác trong máy, bạn nên tạo một môi trường ảo (virtual environment):
```bash
# Tạo môi trường ảo có tên là .venv
python -m venv .venv

# Kích hoạt môi trường ảo (Trên Windows)
.venv\Scripts\activate

# (Hoặc kích hoạt trên Linux/Mac)
source .venv/bin/activate
```
*Lưu ý: Sau khi kích hoạt, bạn sẽ thấy chữ `(.venv)` hiện ở đầu dòng lệnh trong terminal.*

### Bước 2.3: Cài đặt các thư viện (Dependencies)
Chạy lệnh sau để cài đặt tất cả các thư viện cần thiết đã được liệt kê trong file `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 3. Chạy Chương Trình

### Bước 3.1: Mở Terminal với quyền Administrator (Quản trị viên)
Vì hệ thống cần can thiệp sâu vào card mạng để bắt các gói tin (packet sniffing), bạn **BẮT BUỘC** phải chạy terminal với quyền Administrator.
- Tìm `cmd` hoặc `PowerShell` trong thanh tìm kiếm của Windows.
- Nhấp chuột phải và chọn **Run as Administrator**.
- Dùng lệnh `cd` để di chuyển tới thư mục dự án `PBL4`.
- Kích hoạt lại môi trường ảo bằng lệnh `.venv\Scripts\activate` (nếu có sử dụng).

### Bước 3.2: Khởi động hệ thống
Chạy file ứng dụng chính:
```bash
python app.py
```
Nếu thành công, terminal sẽ hiển thị thông báo hệ thống đang chạy và lắng nghe ở cổng `5000`.

### Bước 3.3: Truy cập Giao diện Web (Dashboard)
Mở trình duyệt web của bạn (Chrome, Edge, Firefox,...) và truy cập vào địa chỉ:
👉 **[http://localhost:5000](http://localhost:5000)**

Tại giao diện này, bạn có thể:
- Xem các thống kê mạng trực tiếp (real-time).
- Bật/tắt trình bắt gói tin (Sniffer).
- Xem danh sách các cảnh báo (Alerts) và lịch sử gói tin (Packets).

---

## 4. Mô Phỏng Tấn Công (Để Kiểm Thử)

Hệ thống có đi kèm một công cụ để bạn tự mô phỏng các cuộc tấn công mạng nhằm kiểm tra xem IDS có phát hiện thành công hay không.

### Bước 4.1: Mở thêm một Terminal mới
Mở thêm một cửa sổ terminal mới (cũng cần quyền **Administrator** và **đã kích hoạt môi trường ảo**), trỏ về thư mục `PBL4`.

### Bước 4.2: Chạy các kịch bản tấn công
Sử dụng script `test_attack.py` để gửi các gói tin mô phỏng.

**Chạy tất cả các loại tấn công mô phỏng cùng lúc:**
```bash
python test_attack.py all 127.0.0.1
```

**Hoặc chạy từng loại hình tấn công cụ thể:**
- Mô phỏng quét cổng (Port Scan):
  ```bash
  python test_attack.py port_scan 127.0.0.1
  ```
- Mô phỏng tấn công SYN Flood:
  ```bash
  python test_attack.py syn_flood 127.0.0.1
  ```
- Mô phỏng tấn công UDP Flood:
  ```bash
  python test_attack.py udp_flood 127.0.0.1
  ```
- Mô phỏng tấn công ICMP Flood (Ping Flood):
  ```bash
  python test_attack.py icmp_flood 127.0.0.1
  ```

Sau khi chạy lệnh, hãy quay lại giao diện web Dashboard (hoặc terminal chạy `app.py`) để xem hệ thống bắt được gói tin và phát ra cảnh báo (Alert) màu đỏ.

---

## 5. Tùy Chỉnh Cấu Hình (Nâng Cao)

Bạn có thể thay đổi các thông số cấu hình của hệ thống trong file `config.py`:
- **Giao diện mạng (Network Interface):** Mặc định đang bắt tất cả các card mạng. Bạn có thể chỉ định card cụ thể.
- **Ngưỡng cảnh báo (Thresholds):** Điều chỉnh số lượng gói tin/thời gian để kích hoạt cảnh báo tấn công (ví dụ bao nhiêu gói SYN trong 1 giây thì tính là SYN Flood).
- **Cảnh báo qua Email:** Bật tính năng gửi cảnh báo qua Email bằng cách đổi `EMAIL_ENABLED = True` và điền thông tin SMTP (khuyến nghị dùng App Password của Gmail).

---

**Chúc bạn cài đặt thành công và trải nghiệm tốt hệ thống!**
