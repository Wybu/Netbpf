// src/monitor.c
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* * DEFINITION: Cấu trúc dữ liệu gửi lên User Space (Feature Vector)
 * Cấu trúc này phải khớp (aligned) với cấu trúc bên Python
 */
struct packet_data_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 len;            // Feature: Kích thước gói
    u8  proto;          // Feature: Giao thức (6=TCP, 17=UDP)
    u8  tcp_flags;      // Feature: Các cờ TCP (SYN, ACK, FIN...) - Quan trọng nhất cho ML
    u64 timestamp;      // Feature: Thời gian (nanoseconds)
};

// Kênh truyền dữ liệu tốc độ cao (Perf Ring Buffer)
BPF_PERF_OUTPUT(events);

/*
 * MAIN PROGRAM: XDP Hook
 */
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Khởi tạo struct dữ liệu
    struct packet_data_t pkt = {};
    pkt.timestamp = bpf_ktime_get_ns(); // Lấy thời gian chuẩn kernel

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) return XDP_PASS;

    // Chỉ xử lý gói tin IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Parse IP Header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) return XDP_PASS;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto  = ip->protocol;
    pkt.len    = bpf_ntohs(ip->tot_len); // Độ dài gói tin IP

    // 3. Parse Layer 4 (Transport)
    if (pkt.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
            pkt.src_port = bpf_ntohs(tcp->source);
            pkt.dst_port = bpf_ntohs(tcp->dest);
            
            // KỸ THUẬT QUAN TRỌNG: Lấy TCP Flags
            // TCP Flags nằm ở offset 13 (byte thứ 13) của TCP Header
            // Ép kiểu về u8* để lấy chính xác 8 bit cờ
            u8 *flags_ptr = ((u8 *)tcp) + 13; 
            pkt.tcp_flags = *flags_ptr;
        }
    } 
    else if (pkt.proto == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            pkt.src_port = bpf_ntohs(udp->source);
            pkt.dst_port = bpf_ntohs(udp->dest);
            pkt.tcp_flags = 0; // UDP không có cờ
        }
    }
    // (Optional) Có thể mở rộng ICMP tại đây

    // 4. Submit dữ liệu lên User Space
    events.perf_submit(ctx, &pkt, sizeof(pkt));

    // XDP_PASS: Cho phép gói tin đi qua (Monitoring Mode)
    // XDP_DROP: Nếu muốn chặn
    return XDP_PASS;
}