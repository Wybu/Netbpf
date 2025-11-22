#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// --- ĐEM STRUCT TỪ .H VÀO ĐÂY ---
// Định nghĩa trực tiếp để tránh lỗi "incomplete type"
struct packet_features {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int len;       // Kích thước gói tin
    unsigned int proto;     // 6=TCP, 17=UDP
    unsigned int flags;     // TCP Flags
};
// --------------------------------

// Channel bắn data lên Python
BPF_PERF_OUTPUT(events);

int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct packet_features feat = {}; // Khởi tạo rỗng

    // 1. Parse Ethernet
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) return XDP_PASS;

    // Chỉ lấy IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Parse IP
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) return XDP_PASS;

    // Lấy thông tin cơ bản
    feat.src_ip = ip->saddr;
    feat.dst_ip = ip->daddr;
    feat.proto = ip->protocol;
    feat.len = bpf_ntohs(ip->tot_len);

    // 3. Parse Layer 4
    if (feat.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
            feat.src_port = bpf_ntohs(tcp->source);
            feat.dst_port = bpf_ntohs(tcp->dest);
            unsigned char *flags = ((unsigned char *)tcp) + 13;
            feat.flags = *flags; 
        }
    } 
    else if (feat.proto == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            feat.src_port = bpf_ntohs(udp->source);
            feat.dst_port = bpf_ntohs(udp->dest);
            feat.flags = 0;
        }
    }

    // 4. Submit event
    events.perf_submit(ctx, &feat, sizeof(feat));

    return XDP_PASS;
}