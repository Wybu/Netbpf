#pragma once

// Bao gồm các kiểu dữ liệu chuẩn của Linux
#include <linux/types.h>

// Định nghĩa từ <linux/sched.h> cho độ dài tên tiến trình
#define TASK_COMM_LEN   16

// Cấu trúc dữ liệu cho một sự kiện mạng sẽ được báo cáo
typedef struct net_event {
    __u64 ts;                   // Dấu thời gian (timestamp)
    __u32 pid;                  // Process ID
    __u32 daddr;                // Địa chỉ IPv4 đích
    __u16 dport;                // Cổng (port) đích
    __u64 tx_bytes;             // Số byte đã gửi
    char comm[TASK_COMM_LEN];   // Tên tiến trình
} net_event_t;
