# ============================================================
# IDS Web Application - Flask + SocketIO
# ============================================================

import os
import sys
import threading
import time

# Fix encoding cho Windows console (hỗ trợ emoji)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import psutil
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

import config
from alert_manager import AlertManager
from ids_core import DetectionEngine, PacketSniffer, PacketStats

# --- Khởi tạo Flask App ---
app = Flask(__name__)
app.config["SECRET_KEY"] = "ids_secret_key_pbl4_2024"

# --- Khởi tạo SocketIO ---
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# --- Khởi tạo các components ---
alert_manager = AlertManager(socketio=socketio)
packet_stats = PacketStats()
detection_engine = DetectionEngine(alert_manager=alert_manager)
packet_sniffer = PacketSniffer(
    detection_engine=detection_engine,
    packet_stats=packet_stats,
    socketio=socketio,
)


# ============================================================
# ROUTES
# ============================================================


@app.route("/")
def index():
    """Trang dashboard chính."""
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    """API lấy thống kê mạng."""
    stats = packet_stats.get_stats()
    stats["total_alerts"] = len(alert_manager.alerts)
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    """API lấy danh sách cảnh báo."""
    return jsonify(alert_manager.get_recent_alerts())


@app.route("/api/packets")
def api_packets():
    """API lấy danh sách packets gần nhất."""
    return jsonify(packet_stats.get_recent_packets())


@app.route("/api/alert-stats")
def api_alert_stats():
    """API lấy thống kê cảnh báo."""
    return jsonify(alert_manager.get_alert_stats())


# ============================================================
# SNIFFER CONTROL APIs
# ============================================================


@app.route("/api/sniffer/status")
def api_sniffer_status():
    """API lấy trạng thái sniffer."""
    return jsonify({
        "running": packet_sniffer.running,
        "interface": config.NETWORK_INTERFACE or "Tất cả",
        "filter": config.PACKET_FILTER or "Không",
    })


@app.route("/api/sniffer/start", methods=["POST"])
def api_sniffer_start():
    """API bắt đầu sniffing."""
    if packet_sniffer.running:
        return jsonify({"status": "already_running", "message": "Sniffer đang chạy rồi."})

    # Lấy interface từ request nếu có
    data = request.get_json(silent=True) or {}
    iface = data.get("interface")
    if iface and iface != "all":
        config.NETWORK_INTERFACE = iface

    packet_sniffer.start()
    return jsonify({"status": "started", "message": "Đã bắt đầu bắt gói tin."})


@app.route("/api/sniffer/stop", methods=["POST"])
def api_sniffer_stop():
    """API dừng sniffing."""
    if not packet_sniffer.running:
        return jsonify({"status": "not_running", "message": "Sniffer chưa chạy."})

    packet_sniffer.stop()
    return jsonify({"status": "stopped", "message": "Đã dừng bắt gói tin."})


@app.route("/api/test-attack/<attack_type>", methods=["POST"])
def api_test_attack(attack_type):
    """API kích hoạt mô phỏng tấn công để test dashboard."""
    data = request.get_json(silent=True) or {}
    src_ip = data.get("source_ip", "192.168.1.100")
    detection_engine.trigger_simulated_attack(attack_type, source_ip=src_ip)
    return jsonify({"status": "ok", "message": f"Đã mô phỏng tấn công {attack_type}"})


# ============================================================
# SYSTEM INFO APIs
# ============================================================


@app.route("/api/system-info")
def api_system_info():
    """API lấy thông tin hệ thống."""
    try:
        cpu_percent = psutil.cpu_percent(interval=0)
        memory = psutil.virtual_memory()
        net_io = psutil.net_io_counters()

        return jsonify({
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used": memory.used,
            "memory_total": memory.total,
            "net_bytes_sent": net_io.bytes_sent,
            "net_bytes_recv": net_io.bytes_recv,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/interfaces")
def api_interfaces():
    """API lấy danh sách network interfaces."""
    try:
        interfaces = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            iface_info = {
                "name": name,
                "is_up": stats.get(name, None) and stats[name].isup,
                "addresses": [],
            }
            for addr in addr_list:
                if addr.family.name == "AF_INET":
                    iface_info["addresses"].append({
                        "ip": addr.address,
                        "netmask": addr.netmask,
                    })
            interfaces.append(iface_info)

        # Sắp xếp: interfaces có IP lên trước
        interfaces.sort(key=lambda x: (not x["addresses"], not x["is_up"], x["name"]))
        return jsonify(interfaces)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# SOCKETIO EVENTS
# ============================================================


@socketio.on("connect")
def handle_connect():
    """Xử lý khi client kết nối."""
    print(f"📱 Client kết nối: {threading.current_thread().name}")
    # Gửi danh sách alerts hiện tại
    socketio.emit("initial_alerts", alert_manager.get_recent_alerts())


@socketio.on("disconnect")
def handle_disconnect():
    """Xử lý khi client ngắt kết nối."""
    print(f"📱 Client ngắt kết nối")


# ============================================================
# BACKGROUND TASKS
# ============================================================


def background_stats_emitter():
    """
    Thread chạy nền, emit thống kê mạng đến dashboard mỗi giây.
    """
    while True:
        try:
            stats = packet_stats.get_stats()
            stats["total_alerts"] = len(alert_manager.alerts)
            stats["recent_packets"] = packet_stats.get_recent_packets(30)
            stats["sniffer_running"] = packet_sniffer.running

            socketio.emit("network_update", stats)
            time.sleep(config.DASHBOARD_UPDATE_INTERVAL)
        except Exception as e:
            time.sleep(1)


def background_cleanup():
    """
    Thread chạy nền, dọn dẹp dữ liệu cũ mỗi 60 giây.
    """
    while True:
        try:
            time.sleep(60)
            detection_engine.cleanup()
        except Exception:
            time.sleep(60)


# ============================================================
# MAIN
# ============================================================


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  🛡️  HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG (IDS)")
    print("  📊 Dashboard: http://localhost:{}".format(config.DASHBOARD_PORT))
    print("=" * 70)

    # Khởi động thread emit stats
    stats_thread = threading.Thread(target=background_stats_emitter, daemon=True)
    stats_thread.start()

    # Khởi động thread cleanup
    cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
    cleanup_thread.start()

    # Khởi động packet sniffer
    packet_sniffer.start()

    # Chạy Flask app với SocketIO
    try:
        socketio.run(
            app,
            host=config.DASHBOARD_HOST,
            port=config.DASHBOARD_PORT,
            debug=config.DASHBOARD_DEBUG,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )
    except KeyboardInterrupt:
        print("\n\n🛑 Đang dừng hệ thống IDS...")
        packet_sniffer.stop()
        print("✅ Đã dừng hoàn toàn.")
