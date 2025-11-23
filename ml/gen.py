import csv
import time
import random

OUTPUT_FILE = "/home/quyna/Desktop/DATN_Quy/xdp_project/data/traffic_log.csv"
START_TIME_NS = int(time.time() * 1e9)
DURATION_PER_PHASE = 40 # 40 giay moi pha

def generate_row(timestamp, mode="NORMAL"):
    src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    dst_ip = "192.168.5.134"
    src_port = random.randint(1024, 65535)
    
    # --- KICH BAN LAM LU LAN AI ---
    
    if mode == "NORMAL_BROWSING": 
        # Luot web binh thuong: PPS thap, ACK/PSH
        dst_port = 443
        protocol = 6
        flags = 16 # ACK
        flag_desc = "ACK"
        length = random.randint(100, 1000)
        label = "NORMAL"

    elif mode == "FLASH_CROWD": 
        # [QUAN TRONG] Nguoi dung vao web dong loat (Ssale, Dang ky tin chi)
        # Hien tuong: PPS tang cao, nhieu SYN (moi ket noi)
        # AI se rat de nham cai nay la SYN Flood
        dst_port = 443
        protocol = 6
        flags = 2 # SYN (Giong het tan cong!)
        flag_desc = "SYN"
        length = 64
        label = "NORMAL" # Ban chat van la Normal

    elif mode == "STEALTH_ACK_ATTACK": 
        # [QUAN TRONG] Tan cong ACK Flood
        # Hien tuong: PPS cao vua phai, dung ACK
        # AI se rat de nham cai nay la Normal (tai file)
        dst_port = 80
        protocol = 6
        flags = 16 # ACK (Giong het Normal!)
        flag_desc = "ACK"
        length = random.randint(64, 1400) # Gia lap kich thuoc ngau nhien
        label = "ATTACK" # Ban chat la Attack

    return [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, flag_desc, label]

print(f"🚀 Dang tao du lieu 'NIGHTMARE MODE' (Gay nhieu AI)...")

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp_ns', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'protocol', 'length', 'tcp_flags_raw', 'tcp_flags_desc', 'label'])
    current_time = START_TIME_NS

    # 1. NORMAL THUONG (De doan)
    print("Phase 1: Normal Browsing...")
    for _ in range(DURATION_PER_PHASE):
        for _ in range(random.randint(20, 50)):
            writer.writerow(generate_row(current_time, "NORMAL_BROWSING"))
        current_time += 1_000_000_000

    # 2. FLASH CROWD (Normal nhung giong Attack)
    # Day PPS len 300, nhieu SYN -> Model tuong SYN Flood
    print("Phase 2: Flash Crowd (Gia lap nguoi dung dong)...")
    for _ in range(DURATION_PER_PHASE):
        for _ in range(random.randint(200, 300)):
            writer.writerow(generate_row(current_time, "FLASH_CROWD"))
        current_time += 1_000_000_000

    # 3. STEALTH ACK ATTACK (Attack nhung giong Normal)
    # Dung ACK, PPS khoang 400 -> Model tuong dang tai phim
    print("Phase 3: Stealth ACK Attack...")
    for _ in range(DURATION_PER_PHASE):
        for _ in range(random.randint(300, 500)):
            writer.writerow(generate_row(current_time, "STEALTH_ACK_ATTACK"))
        current_time += 1_000_000_000

print("✅ Xong! Du lieu nay cuc kho phan biet.")
print("👉 Chay dataprep.py va model.py ngay de xem Accuracy tut doc!")