#!/usr/bin/python3
from bcc import BPF
import time
import socket
import struct
import sys

# === CẤU HÌNH ===
INTERFACE = "eth0"  # Tên card mạng trên VMware của bạn (check ifconfig)
SIG_FILE = "signatures.txt"

def ip_to_int(ip_str):
    """Chuyển IP string (192.168.1.1) thành số nguyên (Network Byte Order)"""
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

print(f"🔥 Red Susu Firewall đang khởi động trên {INTERFACE}...")

# 1. Compile và Load chương trình XDP
# BCC sẽ tự đọc file C và compile ngay lúc này
b = BPF(src_file="xdp_prog.c")
fn = b.load_func("xdp_firewall", BPF.XDP)

# 2. Attach vào Interface
print(f"-> Đang gắn XDP hook vào {INTERFACE}...")
b.attach_xdp(INTERFACE, fn, 0)

# 3. Nạp Signatures từ file vào Kernel Map
print(f"-> Đang nạp mẫu nhận diện từ {SIG_FILE}...")
blacklist_map = b.get_table("blacklist")

try:
    with open(SIG_FILE, "r") as f:
        for line in f:
            ip = line.strip()
            if not ip: continue
            
            # Convert IP sang int và đẩy vào Map
            ip_int = ip_to_int(ip)
            # Key là IP, Value là 1 (đánh dấu là có)
            blacklist_map[b.Key(ip_int)] = b.Leaf(1)
            print(f"   + Đã thêm mẫu: {ip}")
except FileNotFoundError:
    print("❌ Lỗi: Không tìm thấy file signatures.txt")
    sys.exit(1)

print("\n✅ Hệ thống đã sẵn sàng! Đang lắng nghe gói tin...")
print("Nhấn Ctrl+C để dừng.\n")
print("LOGS:")
print("-" * 20)

# 4. Vòng lặp đọc Log từ Kernel (bpf_trace_printk)
try:
    while True:
        # Đọc và in log real-time
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"🚨 {msg.decode('utf-8')}")
except KeyboardInterrupt:
    print("\n\nĐang tắt hệ thống...")
finally:
    # 5. Dọn dẹp: Gỡ bỏ XDP khỏi interface khi tắt
    b.remove_xdp(INTERFACE, 0)
    print("👋 Đã gỡ XDP hook. Mạng trở lại bình thường.")