import time
import joblib
import pandas as pd
import os
import sys

# --- CAU HINH ---
# Duong dan tuyet doi den file log (giong dataprep.py)
LOG_FILE = "/home/quyna/Desktop/DATN_Quy/xdp_project/data/traffic_log.csv"
MODEL_FILE = "rf_model.pkl"

# Cac cot Feature ma Model yeu cau (Phai dung thu tu luc train)
FEATURE_COLS = ['pps', 'bps', 'avg_len', 'syn_count', 'unique_dst_ports', 'syn_rate']

def load_model():
    print(f"Dang load model tu {MODEL_FILE}...")
    try:
        model = joblib.load(MODEL_FILE)
        return model
    except FileNotFoundError:
        print("Loi: Khong tim thay file model. Hay chay model.py truoc!")
        sys.exit(1)

def follow(thefile):
    """Ham doc file lien tuc (giong lenh tail -f)"""
    thefile.seek(0, 2) # Di chuyen den cuoi file
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1) # Ngu mot chut neu khong co du lieu moi
            continue
        yield line

def extract_features_from_window(window_packets):
    """Tinh toan Feature tu danh sach goi tin trong 1 giay"""
    count = len(window_packets)
    if count == 0:
        return None

    total_len = 0
    syn_count = 0
    dst_ports = set()

    # Cau truc line CSV: 
    # 0:timestamp, 1:src, 2:dst, 3:sport, 4:dport, 5:proto, 6:len, 7:flags, ...
    
    for pkt in window_packets:
        try:
            parts = pkt.strip().split(',')
            length = int(parts[6])
            flags = int(parts[7])
            dport = parts[4]

            total_len += length
            dst_ports.add(dport)
            
            # Kiem tra co SYN (Flag 2)
            if flags == 2:
                syn_count += 1
        except:
            continue # Bo qua dong loi

    # Tinh toan cac chi so
    pps = count
    bps = total_len
    avg_len = total_len / count
    unique_dst_ports = len(dst_ports)
    syn_rate = syn_count / count

    # Tao DataFrame 1 dong de du doan
    df = pd.DataFrame([[pps, bps, avg_len, syn_count, unique_dst_ports, syn_rate]], 
                      columns=FEATURE_COLS)
    return df

def main():
    model = load_model()
    
    print(f"Dang giam sat file: {LOG_FILE}")
    print("He thong IPS san sang! Dang cho du lieu...")
    print("-" * 50)
    print(f"{'THOI GIAN':<10} | {'PPS':<5} | {'SYN%':<5} | {'TRANG THAI':<15}")
    print("-" * 50)

    try:
        logfile = open(LOG_FILE, "r")
    except FileNotFoundError:
        print("Loi: Khong tim thay file log. Hay chay collector.py truoc!")
        sys.exit(1)

    # Buffer de luu goi tin trong giay hien tai
    current_window = []
    last_second = None

    # Vong lap doc realtime
    loglines = follow(logfile)
    
    for line in loglines:
        try:
            # Lay timestamp tu cot dau tien
            parts = line.split(',')
            if not parts[0].isdigit(): continue # Bo qua header hoac dong loi
            
            ts_ns = int(parts[0])
            current_second = ts_ns // 1_000_000_000 # Chuyen ve giay
            
            if last_second is None:
                last_second = current_second

            # Neu van o trong giay cu -> Them vao buffer
            if current_second == last_second:
                current_window.append(line)
            else:
                # --- DA SANG GIAY MOI -> XU LY GIAY CU ---
                if current_window:
                    # 1. Trich xuat feature
                    features = extract_features_from_window(current_window)
                    
                    if features is not None:
                        # 2. Du doan (Predict)
                        prediction = model.predict(features)[0]
                        
                        # 3. Hien thi ket qua
                        pps = features['pps'][0]
                        syn_rate = features['syn_rate'][0]
                        
                        status = "BINH THUONG"
                        color_code = "" # Khong mau
                        
                        if prediction == 1:
                            status = "!!! TAN CONG !!!"
                            # In mau do neu tan cong (tren terminal Linux)
                            print(f"\033[91m{last_second} | {pps:<5} | {syn_rate:.2f} | {status}\033[0m")
                        else:
                            # In binh thuong, ghi de len dong cu de do spam man hinh
                            # sys.stdout.write(f"\r{last_second} | {pps:<5} | {syn_rate:.2f} | {status}")
                            # sys.stdout.flush()
                            print(f"{last_second} | {pps:<5} | {syn_rate:.2f} | {status}")

                # Reset cho giay moi
                current_window = [line]
                last_second = current_second

        except ValueError:
            continue
        except IndexError:
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDa dung he thong giam sat.")