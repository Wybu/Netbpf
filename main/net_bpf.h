#ifndef NET_BPF_H
#define NET_BPF_H

// Cấu trúc data gửi từ Kernel lên Python
struct packet_features {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int len;       // Kích thước gói tin (quan trọng cho ML)
    unsigned int proto;     // 6=TCP, 17=UDP, 1=ICMP
    unsigned int flags;     // TCP Flags (SYN, ACK, FIN...)
};

#endif