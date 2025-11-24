import csv
import time
import random
import ipaddress
import numpy as np

# --- CAU HINH ---
OUTPUT_FILE = "/home/quyna/Desktop/DATN_Quy/xdp_project/data/traffic_log.csv"
START_TIME = int(time.time()) - 3600 # Bat dau tu 1 tieng truoc
CURRENT_TIME_NS = START_TIME * 1_000_000_000

# --- CAC HAM HO TRO ---
def get_random_ip():
    return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

def get_local_ip():
    return f"192.168.1.{random.randint(1, 254)}"

# --- HAM TAO 1 DONG LOG ---
def generate_row(timestamp, profile):
    dst_ip = "192.168.5.134" # IP Server
    
    # 1. NORMAL (Luot web, Chat, DNS)
    if profile == "NORMAL":
        src_ip = get_local_ip()
        src_port = random.randint(1024, 65535)
        # Mix giua Web (80/443) va DNS (53)
        dst_port = random.choice([80, 443, 443, 443, 53, 8080])
        
        if dst_port == 53: # DNS
            protocol = 17 # UDP
            flags = 0
            flag_desc = "."
            length = random.randint(60, 120)
        else: # Web
            protocol = 6 # TCP
            flags = random.choice([16, 24]) # ACK or PSH+ACK
            flag_desc = "ACK" if flags == 16 else "PSH|ACK"
            # Length bien thien manh (request nho, response to)
            length = random.choice([64, 512, 1200, 1500])
            
        label = "NORMAL"

    # 2. TCP SYN FLOOD (Layer 4 - DoS)
    elif profile == "SYN_FLOOD":
        src_ip = get_random_ip() # IP Spoofing
        src_port = random.randint(1024, 65535)
        dst_port = 80
        protocol = 6
        length = random.randint(54, 64) # Goi tin nho
        flags = 2 # SYN Only
        flag_desc = "SYN"
        label = "ATTACK"

    # 3. UDP FLOOD (Layer 4 - Volumetric)
    elif profile == "UDP_FLOOD":
        src_ip = get_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 65535) # Ban vao cong ngau nhien
        protocol = 17 # UDP
        length = 1400 # Goi tin to de chiem bang thong
        flags = 0
        flag_desc = "."
        label = "ATTACK"

    # 4. TCP ACK FLOOD (Layer 4 - Mimicry)
    elif profile == "ACK_FLOOD":
        src_ip = get_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = 80
        protocol = 6
        length = 64
        flags = 16 # ACK (Gia mao traffic hop le)
        flag_desc = "ACK"
        label = "ATTACK"

    # 5. ICMP FLOOD (Layer 3 - Ping Flood)
    elif profile == "ICMP_FLOOD":
        src_ip = get_random_ip()
        src_port = 0
        dst_port = 0
        protocol = 1 # ICMP
        length = 64
        flags = 0
        flag_desc = "."
        label = "ATTACK"

    # 6. PORT SCAN (Layer 4 - Reconnaissance)
    elif profile == "PORT_SCAN":
        src_ip = "10.10.10.10" # Thuong den tu 1 IP co dinh
        src_port = 12345
        dst_port = random.randint(1, 10000) # Quet lien tuc cac cong
        protocol = 6
        length = 64
        flags = 2 # SYN Scan
        flag_desc = "SYN"
        label = "ATTACK"

    return [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, flag_desc, label]

# --- MAIN LOGIC ---
print(f"🚀 Dang tao Dataset Tong Hop (L3 & L4 Attacks)...")
print(f"📂 File luu tai: {OUTPUT_FILE}")

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label'])
    
    # --- KICH BAN 60 PHUT ---
    # Cau truc: [Ten Profile, Thoi gian (giay), PPS (Goi/giay)]
    scenarios = [
        ("NORMAL", 600, 30),       # 10p dau binh thuong
        ("SYN_FLOOD", 120, 2000),  # 2p tan cong SYN manh
        ("NORMAL", 300, 40),       # 5p binh thuong
        ("UDP_FLOOD", 120, 1500),  # 2p tan cong UDP
        ("NORMAL", 300, 30),       # 5p binh thuong
        ("ACK_FLOOD", 120, 1800),  # 2p tan cong ACK
        ("NORMAL", 300, 50),       # 5p binh thuong
        ("ICMP_FLOOD", 120, 1000), # 2p Ping Flood
        ("NORMAL", 300, 30),       # 5p binh thuong
        ("PORT_SCAN", 60, 800),    # 1p Quet cong
        ("NORMAL", 600, 30)        # 10p cuoi binh thuong
    ]

    total_packets = 0
    
    for profile, duration, pps in scenarios:
        print(f"   + Generating {profile} for {duration}s (PPS: {pps})...")
        
        for _ in range(duration):
            # Tao so luong goi tin tuong ung voi PPS
            # Them random jitter de du lieu tu nhien hon (+- 20%)
            current_pps = int(pps * random.uniform(0.8, 1.2))
            
            for _ in range(current_pps):
                row = generate_row(CURRENT_TIME_NS, profile)
                writer.writerow(row)
                total_packets += 1
            
            CURRENT_TIME_NS += 1_000_000_000 # Tang 1 giay

print("-" * 30)
print(f"✅ XONG! Tong so goi tin: {total_packets}")
print("👉 Dataset nay bao gom day du cac loai tan cong tieu bieu.")
print("👉 Hay chay lai: python3 dataprep.py -> python3 model.py")