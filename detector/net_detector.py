#!/usr/bin/python3

import os
import sys
import time
import ctypes
import socket
import struct
from bcc import BPF

# Định nghĩa cấu trúc Event trong Python để khớp với net_bpf.h
TASK_COMM_LEN = 16
class Event(ctypes.Structure):
    _fields_ = [
        ('ts', ctypes.c_uint64),
        ('pid', ctypes.c_uint32),
        ('daddr', ctypes.c_uint32),
        ('dport', ctypes.c_uint16),
        ('tx_bytes', ctypes.c_uint64),
        ('comm', ctypes.c_char * TASK_COMM_LEN),
    ]

# Hàm callback để xử lý và in sự kiện nhận được từ kernel
def print_event(_ctx, data, _size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    # Chuyển đổi địa chỉ IP từ dạng số nguyên sang dạng chuỗi
    dest_ip = socket.inet_ntoa(struct.pack("=L", event.daddr))

    print("%-12.6f %-6d %-16s %s:%-5d %-10d" % (
        int(event.ts / 1e6),
        event.pid,
        event.comm.decode('utf-8', 'replace'),
        dest_ip,
        event.dport,
        event.tx_bytes
    ))

def runas_root() -> bool:
    return os.getuid() == 0

def main():
    if not runas_root():
        print("Bạn phải chạy chương trình này với quyền root hoặc sudo.")
        sys.exit()

    # Tải chương trình eBPF
    b = BPF(src_file="net_bpf.c")

    # Mở ring buffer và gắn hàm callback
    b['net_events'].open_ring_buffer(print_event)

    print("Đang giám sát các kết nối mạng... Nhấn Ctrl-C để thoát.")
    print("%-12s %-6s %-16s %-21s %-10s" % ("TS(ms)", "PID", "COMM", "DESTINATION", "TX_BYTES"))

    # Vòng lặp để đọc sự kiện từ buffer
    while 1:
        try:
            b.ring_buffer_poll()
        except KeyboardInterrupt:
            sys.exit()

if __name__ == '__main__':
    main()
