# machinelearning/dataprep.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# CẤU HÌNH ĐƯỜNG DẪN
RAW_LOG_PATH = "xdp_project/data/traffic_log.csv"
OUTPUT_TRAIN = "train_data.csv"
OUTPUT_TEST = "test_data.csv"

def load_and_process_data(filepath):
    print(f"[*] Đang đọc dữ liệu từ {filepath}...")
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print("❌ Lỗi: Không tìm thấy file log. Hãy chạy collector.py trước!")
        return None

    # 1. Chuyển timestamp từ nanoseconds sang datetime
    df['datetime'] = pd.to_datetime(df['timestamp_ns'], unit='ns')
    df = df.set_index('datetime')

    print("[*] Đang trích xuất đặc trưng (Feature Engineering)...")
    
    # 2. Gom nhóm theo từng giây (1 Second Window)
    # Đây là bước biến Raw Data -> Flow Data
    df_resampled = df.resample('1S').agg({
        'length': ['count', 'sum', 'mean'],     # PPS, BPS, Avg Len
        'tcp_flags_raw': lambda x: (x == 2).sum(), # Đếm số lượng gói SYN (Flag=2)
        'dst_port': 'nunique'                   # Đếm số port đích khác nhau
    })

    # Làm phẳng MultiIndex columns
    df_resampled.columns = ['pps', 'bps', 'avg_len', 'syn_count', 'unique_dst_ports']
    
    # Loại bỏ các giây không có traffic
    df_resampled = df_resampled[df_resampled['pps'] > 0].copy()

    # 3. Tạo thêm Feature phái sinh
    # Tỷ lệ SYN (SYN Rate): Nếu gần 1.0 -> Khả năng cao là SYN Flood
    df_resampled['syn_rate'] = df_resampled['syn_count'] / df_resampled['pps']

    return df_resampled

def auto_label_data(df):
    """
    Hàm giả lập gán nhãn (Labeling) để Train Model.
    Trong thực tế, bạn cần tấn công thật để có nhãn chính xác.
    """
    print("[*] Đang tự động gán nhãn (Heuristic Labeling)...")
    
    # Rule giả định:
    # - Nếu PPS > 1000 -> DDoS Volumetric
    # - Nếu SYN Rate > 0.9 và PPS > 100 -> SYN Flood
    # - Nếu Unique Ports > 50 -> Port Scan
    
    conditions = [
        (df['pps'] > 1000) | 
        ((df['syn_rate'] > 0.9) & (df['pps'] > 100)) |
        (df['unique_dst_ports'] > 50)
    ]
    
    # 1 = Attack, 0 = Normal
    df['label'] = np.select(conditions, [1], default=0)
    
    print(f"   + Số mẫu bình thường: {len(df[df['label']==0])}")
    print(f"   + Số mẫu tấn công: {len(df[df['label']==1])}")
    return df

if __name__ == "__main__":
    # Chạy quy trình
    df_features = load_and_process_data(RAW_LOG_PATH)
    
    if df_features is not None:
        df_labeled = auto_label_data(df_features)
        
        # Chia train/test (80% train, 20% test)
        X = df_labeled.drop('label', axis=1)
        y = df_labeled['label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Gộp lại để lưu file CSV
        train_set = pd.concat([X_train, y_train], axis=1)
        test_set = pd.concat([X_test, y_test], axis=1)
        
        train_set.to_csv(OUTPUT_TRAIN, index=False)
        test_set.to_csv(OUTPUT_TEST, index=False)
        
        print(f"✅ Đã xong! Dữ liệu lưu tại {OUTPUT_TRAIN} và {OUTPUT_TEST}")