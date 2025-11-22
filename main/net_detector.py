#!/usr/bin/python3
from bcc import BPF
import socket
import struct
import csv
import time
import sys
import os

# --- CẤU HÌNH ---
INTERFACE = "eth0" # Thay bằng tên card mạng của bạn
LOG_FILE = "log.csv"

# Định nghĩa struct ctypes khớp với struct trong C để decode
class PacketFeatures(dict):
    def __init__(self, src_ip, dst_ip, src_port, dst_port, length, proto, flags):
        self['ts'] = time.time() # Timestamp cho ML
        self['src_ip'] = socket.inet_ntoa(struct.pack("I", src_ip))
        self['dst_ip'] = socket.inet_ntoa(struct.pack("I", dst_ip))
        self['src_port'] = src_port
        self['dst_port'] = dst_port
        self['len'] = length
        self['proto'] = proto
        self['flags'] = flags

# Khởi tạo file CSV
file_exists = os.path.isfile(LOG_FILE)
csv_file = open(LOG_FILE, 'a', newline='')
fieldnames = ['ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'len', 'proto', 'flags']
writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

if not file_exists:
    writer.writeheader()
    print(f"📝 Đã tạo file mới: {LOG_FILE}")
else:
    print(f"📝 Ghi tiếp vào file: {LOG_FILE}")

print(f"🔥 Red Susu Detector đang chạy trên {INTERFACE}...")
print(f"Đang thu thập dữ liệu... (Nhấn Ctrl+C để dừng)")

# Load BPF
b = BPF(src_file="net_bpf.c") # -I. để include file .h cùng thư mục
fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp(INTERFACE, fn, 0)

# Callback xử lý sự kiện từ Kernel
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    
    # Tạo object features
    features = PacketFeatures(
        event.src_ip, event.dst_ip, 
        event.src_port, event.dst_port,
        event.len, event.proto, event.flags
    )
    
    # Ghi vào CSV
    writer.writerow(features)
    
    # In ra màn hình cho vui (Optional)
    print(f"Pack: {features['src_ip']} -> {features['dst_ip']} | Proto: {features['proto']} | Flags: {features['flags']}")

# Mở buffer để lắng nghe
b["events"].open_perf_buffer(handle_event)

try:
    while True:
        # poll() sẽ gọi handle_event khi có dữ liệu
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🛑 Đang dừng...")
finally:
    b.remove_xdp(INTERFACE, 0)
    csv_file.close()
    print("👋 Đã lưu dữ liệu. File log.csv đã sẵn sàng cho ML!")