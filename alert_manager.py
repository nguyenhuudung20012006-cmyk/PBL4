# ============================================================
# Alert Manager - Quản lý cảnh báo IDS
# ============================================================

import logging
import smtplib
import sys
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from colorama import Fore, Style, init

import config

# Khởi tạo colorama cho Windows
init(autoreset=True)

# Thiết lập logger
logger = logging.getLogger("IDS_Alert")
logger.setLevel(logging.DEBUG)

# File handler
file_handler = logging.FileHandler(config.ALERT_LOG_FILE, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


class Alert:
    """Đối tượng cảnh báo chứa thông tin về sự kiện bất thường."""

    def __init__(self, alert_type, severity, source_ip, description, details=None):
        self.id = id(self)
        self.timestamp = datetime.now()
        self.alert_type = alert_type      # Loại tấn công: PORT_SCAN, SYN_FLOOD, ...
        self.severity = severity          # Mức cảnh báo: LOW, MEDIUM, HIGH, CRITICAL
        self.source_ip = source_ip        # IP nguồn tấn công
        self.description = description    # Mô tả ngắn
        self.details = details or {}      # Chi tiết bổ sung

    def to_dict(self):
        """Chuyển đổi alert thành dictionary cho API/SocketIO."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "description": self.description,
            "details": self.details,
        }

    def __str__(self):
        return (
            f"[{self.timestamp.strftime('%H:%M:%S')}] "
            f"[{self.severity}] {self.alert_type} - "
            f"Source: {self.source_ip} - {self.description}"
        )


class AlertManager:
    """Quản lý việc tạo và phân phối cảnh báo."""

    # Màu sắc cho console theo mức cảnh báo
    SEVERITY_COLORS = {
        "LOW": Fore.CYAN,
        "MEDIUM": Fore.YELLOW,
        "HIGH": Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    # Biểu tượng cho console
    SEVERITY_ICONS = {
        "LOW": "ℹ️ ",
        "MEDIUM": "⚠️ ",
        "HIGH": "🔴",
        "CRITICAL": "🚨",
    }

    def __init__(self, socketio=None):
        """
        Khởi tạo AlertManager.
        
        Args:
            socketio: Flask-SocketIO instance để emit alerts real-time
        """
        self.socketio = socketio
        self.alerts = []
        self.lock = threading.Lock()

    def create_alert(self, alert_type, severity, source_ip, description, details=None):
        """
        Tạo và xử lý cảnh báo mới.
        
        Args:
            alert_type: Loại tấn công (PORT_SCAN, SYN_FLOOD, ...)
            severity: Mức cảnh báo (LOW, MEDIUM, HIGH, CRITICAL)
            source_ip: IP nguồn
            description: Mô tả
            details: Chi tiết bổ sung
        """
        alert = Alert(alert_type, severity, source_ip, description, details)

        with self.lock:
            self.alerts.append(alert)
            # Giữ tối đa MAX_RECENT_ALERTS alerts
            if len(self.alerts) > config.MAX_RECENT_ALERTS:
                self.alerts = self.alerts[-config.MAX_RECENT_ALERTS:]

        # Gửi cảnh báo qua các kênh
        self._console_alert(alert)
        self._log_alert(alert)

        # Gửi qua WebSocket nếu có
        if self.socketio:
            self.socketio.emit("new_alert", alert.to_dict())

        # Gửi email nếu đủ mức cảnh báo
        if config.EMAIL_ENABLED:
            alert_level = config.ALERT_LEVELS.get(severity, 0)
            email_level = config.ALERT_LEVELS.get(config.EMAIL_ALERT_LEVEL, 3)
            if alert_level >= email_level:
                # Gửi email trong thread riêng để không block
                threading.Thread(
                    target=self._email_alert, args=(alert,), daemon=True
                ).start()

        return alert

    def _console_alert(self, alert):
        """In cảnh báo ra console với màu sắc."""
        color = self.SEVERITY_COLORS.get(alert.severity, Fore.WHITE)
        icon = self.SEVERITY_ICONS.get(alert.severity, "")

        separator = color + "=" * 70
        print(separator)
        print(
            f"{color}{icon} [{alert.severity}] {alert.alert_type}"
            f"{Style.RESET_ALL}"
        )
        print(f"{color}   Thời gian : {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{color}   IP nguồn  : {alert.source_ip}")
        print(f"{color}   Mô tả     : {alert.description}")
        if alert.details:
            for key, value in alert.details.items():
                print(f"{color}   {key:10s}: {value}")
        print(separator + Style.RESET_ALL)

    def _log_alert(self, alert):
        """Ghi cảnh báo vào file log."""
        log_msg = (
            f"[{alert.severity}] {alert.alert_type} | "
            f"IP: {alert.source_ip} | {alert.description}"
        )
        if alert.details:
            details_str = " | ".join(f"{k}={v}" for k, v in alert.details.items())
            log_msg += f" | {details_str}"

        level_map = {
            "LOW": logging.INFO,
            "MEDIUM": logging.WARNING,
            "HIGH": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        logger.log(level_map.get(alert.severity, logging.WARNING), log_msg)

    def _email_alert(self, alert):
        """Gửi cảnh báo qua email."""
        try:
            email_cfg = config.EMAIL_CONFIG

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[IDS Alert - {alert.severity}] {alert.alert_type} từ {alert.source_ip}"
            msg["From"] = email_cfg["sender_email"]
            msg["To"] = email_cfg["receiver_email"]

            # Nội dung email HTML
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #1a1a2e; color: #eee; padding: 20px;">
                <div style="background: linear-gradient(135deg, #16213e, #0f3460); padding: 20px; border-radius: 10px; border-left: 5px solid {'#ff4757' if alert.severity in ('HIGH', 'CRITICAL') else '#ffa502'};">
                    <h2 style="color: #00d4ff;">🛡️ IDS Alert - {alert.severity}</h2>
                    <table style="width: 100%; color: #eee;">
                        <tr><td style="padding: 8px;"><strong>Loại tấn công:</strong></td><td>{alert.alert_type}</td></tr>
                        <tr><td style="padding: 8px;"><strong>Mức cảnh báo:</strong></td><td style="color: {'#ff4757' if alert.severity in ('HIGH', 'CRITICAL') else '#ffa502'};">{alert.severity}</td></tr>
                        <tr><td style="padding: 8px;"><strong>IP nguồn:</strong></td><td>{alert.source_ip}</td></tr>
                        <tr><td style="padding: 8px;"><strong>Thời gian:</strong></td><td>{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                        <tr><td style="padding: 8px;"><strong>Mô tả:</strong></td><td>{alert.description}</td></tr>
                    </table>
                    {"".join(f'<p style="padding: 4px 8px;"><strong>{k}:</strong> {v}</p>' for k, v in (alert.details or {}).items())}
                    <hr style="border-color: #333;">
                    <p style="font-size: 12px; color: #888;">Đây là email tự động từ Hệ thống IDS. Vui lòng kiểm tra ngay.</p>
                </div>
            </body>
            </html>
            """
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"]) as server:
                server.starttls()
                server.login(email_cfg["sender_email"], email_cfg["sender_password"])
                server.sendmail(
                    email_cfg["sender_email"],
                    email_cfg["receiver_email"],
                    msg.as_string(),
                )
            logger.info(f"Email cảnh báo đã gửi cho {email_cfg['receiver_email']}")
        except Exception as e:
            logger.error(f"Lỗi gửi email cảnh báo: {e}")

    def get_recent_alerts(self, count=None):
        """Lấy danh sách cảnh báo gần nhất."""
        count = count or config.MAX_RECENT_ALERTS
        with self.lock:
            return [a.to_dict() for a in self.alerts[-count:]]

    def get_alert_stats(self):
        """Lấy thống kê cảnh báo."""
        with self.lock:
            stats = {
                "total": len(self.alerts),
                "by_severity": {},
                "by_type": {},
            }
            for alert in self.alerts:
                stats["by_severity"][alert.severity] = (
                    stats["by_severity"].get(alert.severity, 0) + 1
                )
                stats["by_type"][alert.alert_type] = (
                    stats["by_type"].get(alert.alert_type, 0) + 1
                )
            return stats
