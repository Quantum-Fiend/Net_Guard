/*
 * Net_Guard - Protocol Parser Implementation
 * Parse Ethernet, IPv4/IPv6, TCP/UDP/ICMP headers
 */

#include "netguard_internal.h"

/* Network byte order conversion */
#define NTOH16(x) ntohs(x)
#define NTOH32(x) ntohl(x)

/* Ethernet types */
#define ETH_TYPE_IPV4   0x0800
#define ETH_TYPE_IPV6   0x86DD
#define ETH_TYPE_ARP    0x0806
#define ETH_TYPE_VLAN   0x8100

/* IP protocols */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
#define IP_PROTO_ICMPV6 58

/* Parse Ethernet header */
bool parse_ethernet(const uint8_t* data, uint32_t length, EthernetHeader* eth) {
    if (!data || !eth || length < 14) {
        return false;
    }
    
    memcpy(eth->dst_mac, data, 6);
    memcpy(eth->src_mac, data + 6, 6);
    eth->ethertype = NTOH16(*(uint16_t*)(data + 12));
    
    /* Handle VLAN tags */
    if (eth->ethertype == ETH_TYPE_VLAN && length >= 18) {
        eth->ethertype = NTOH16(*(uint16_t*)(data + 16));
    }
    
    return true;
}

/* Parse IPv4 header */
bool parse_ipv4(const uint8_t* data, uint32_t length, IPv4Header* ip, uint32_t* header_len) {
    if (!data || !ip || length < 20) {
        return false;
    }
    
    ip->version_ihl = data[0];
    uint8_t version = (ip->version_ihl >> 4) & 0x0F;
    uint8_t ihl = ip->version_ihl & 0x0F;
    
    if (version != 4) {
        return false;
    }
    
    *header_len = ihl * 4;
    if (*header_len < 20 || length < *header_len) {
        return false;
    }
    
    ip->tos = data[1];
    ip->total_length = NTOH16(*(uint16_t*)(data + 2));
    ip->identification = NTOH16(*(uint16_t*)(data + 4));
    ip->flags_fragment = NTOH16(*(uint16_t*)(data + 6));
    ip->ttl = data[8];
    ip->protocol = data[9];
    ip->checksum = NTOH16(*(uint16_t*)(data + 10));
    ip->src_ip = NTOH32(*(uint32_t*)(data + 12));
    ip->dst_ip = NTOH32(*(uint32_t*)(data + 16));
    
    return true;
}

/* Parse IPv6 header */
bool parse_ipv6(const uint8_t* data, uint32_t length, IPv6Header* ip) {
    if (!data || !ip || length < 40) {
        return false;
    }
    
    ip->version_class_flow = NTOH32(*(uint32_t*)data);
    uint8_t version = (ip->version_class_flow >> 28) & 0x0F;
    
    if (version != 6) {
        return false;
    }
    
    ip->payload_length = NTOH16(*(uint16_t*)(data + 4));
    ip->next_header = data[6];
    ip->hop_limit = data[7];
    memcpy(ip->src_ip, data + 8, 16);
    memcpy(ip->dst_ip, data + 24, 16);
    
    return true;
}

/* Parse TCP header */
bool parse_tcp(const uint8_t* data, uint32_t length, TCPHeader* tcp, uint32_t* header_len) {
    if (!data || !tcp || length < 20) {
        return false;
    }
    
    tcp->src_port = NTOH16(*(uint16_t*)(data));
    tcp->dst_port = NTOH16(*(uint16_t*)(data + 2));
    tcp->seq_num = NTOH32(*(uint32_t*)(data + 4));
    tcp->ack_num = NTOH32(*(uint32_t*)(data + 8));
    tcp->data_offset = data[12];
    tcp->flags = data[13];
    tcp->window = NTOH16(*(uint16_t*)(data + 14));
    tcp->checksum = NTOH16(*(uint16_t*)(data + 16));
    tcp->urgent_ptr = NTOH16(*(uint16_t*)(data + 18));
    
    *header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
    if (*header_len < 20 || length < *header_len) {
        return false;
    }
    
    return true;
}

/* Parse UDP header */
bool parse_udp(const uint8_t* data, uint32_t length, UDPHeader* udp) {
    if (!data || !udp || length < 8) {
        return false;
    }
    
    udp->src_port = NTOH16(*(uint16_t*)(data));
    udp->dst_port = NTOH16(*(uint16_t*)(data + 2));
    udp->length = NTOH16(*(uint16_t*)(data + 4));
    udp->checksum = NTOH16(*(uint16_t*)(data + 6));
    
    return true;
}

/* Parse ICMP header */
bool parse_icmp(const uint8_t* data, uint32_t length, ICMPHeader* icmp) {
    if (!data || !icmp || length < 8) {
        return false;
    }
    
    icmp->type = data[0];
    icmp->code = data[1];
    icmp->checksum = NTOH16(*(uint16_t*)(data + 2));
    icmp->rest = NTOH32(*(uint32_t*)(data + 4));
    
    return true;
}

/* Parse complete packet */
bool parse_packet(const uint8_t* data, uint32_t length, uint64_t timestamp, ParsedPacket* packet) {
    if (!data || !packet || length < 14) {
        return false;
    }
    
    memset(packet, 0, sizeof(ParsedPacket));
    packet->timestamp_us = timestamp;
    packet->capture_length = length;
    packet->wire_length = length;
    
    /* Store raw data reference */
    packet->raw_data = (uint8_t*)data;
    packet->raw_length = length;
    
    uint32_t offset = 0;
    
    /* Parse Ethernet */
    if (!parse_ethernet(data + offset, length - offset, &packet->eth)) {
        return false;
    }
    packet->has_eth = true;
    offset += 14;
    
    /* Handle VLAN */
    if (packet->eth.ethertype == ETH_TYPE_VLAN && length > offset + 4) {
        offset += 4;
        packet->eth.ethertype = NTOH16(*(uint16_t*)(data + offset - 2));
    }
    
    /* Parse IP layer */
    if (packet->eth.ethertype == ETH_TYPE_IPV4) {
        uint32_t ip_header_len;
        if (!parse_ipv4(data + offset, length - offset, &packet->ip.ipv4, &ip_header_len)) {
            return true;  /* Partial parse is OK */
        }
        packet->has_ip = true;
        packet->is_ipv6 = false;
        offset += ip_header_len;
        
        /* Parse transport layer */
        switch (packet->ip.ipv4.protocol) {
            case IP_PROTO_TCP: {
                uint32_t tcp_header_len;
                if (parse_tcp(data + offset, length - offset, &packet->transport.tcp, &tcp_header_len)) {
                    packet->has_transport = true;
                    packet->transport_proto = PROTO_TCP;
                    offset += tcp_header_len;
                    
                    /* Extract payload */
                    if (offset < length) {
                        packet->payload = (uint8_t*)(data + offset);
                        packet->payload_length = length - offset;
                    }
                }
                break;
            }
            case IP_PROTO_UDP: {
                if (parse_udp(data + offset, length - offset, &packet->transport.udp)) {
                    packet->has_transport = true;
                    packet->transport_proto = PROTO_UDP;
                    offset += 8;
                    
                    /* Extract payload */
                    if (offset < length) {
                        packet->payload = (uint8_t*)(data + offset);
                        packet->payload_length = length - offset;
                    }
                }
                break;
            }
            case IP_PROTO_ICMP: {
                if (parse_icmp(data + offset, length - offset, &packet->transport.icmp)) {
                    packet->has_transport = true;
                    packet->transport_proto = PROTO_ICMP;
                    offset += 8;
                    
                    if (offset < length) {
                        packet->payload = (uint8_t*)(data + offset);
                        packet->payload_length = length - offset;
                    }
                }
                break;
            }
        }
        
        /* Calculate flow hash */
        if (packet->has_transport && (packet->transport_proto == PROTO_TCP || packet->transport_proto == PROTO_UDP)) {
            uint16_t src_port = (packet->transport_proto == PROTO_TCP) ? 
                                packet->transport.tcp.src_port : packet->transport.udp.src_port;
            uint16_t dst_port = (packet->transport_proto == PROTO_TCP) ? 
                                packet->transport.tcp.dst_port : packet->transport.udp.dst_port;
            packet->flow_hash = netguard_flow_hash(packet->ip.ipv4.src_ip, packet->ip.ipv4.dst_ip,
                                                   src_port, dst_port, packet->ip.ipv4.protocol);
        }
    }
    else if (packet->eth.ethertype == ETH_TYPE_IPV6) {
        if (!parse_ipv6(data + offset, length - offset, &packet->ip.ipv6)) {
            return true;
        }
        packet->has_ip = true;
        packet->is_ipv6 = true;
        offset += 40;
        
        /* Parse transport based on next_header */
        uint8_t next_hdr = packet->ip.ipv6.next_header;
        switch (next_hdr) {
            case IP_PROTO_TCP: {
                uint32_t tcp_header_len;
                if (parse_tcp(data + offset, length - offset, &packet->transport.tcp, &tcp_header_len)) {
                    packet->has_transport = true;
                    packet->transport_proto = PROTO_TCP;
                    offset += tcp_header_len;
                }
                break;
            }
            case IP_PROTO_UDP: {
                if (parse_udp(data + offset, length - offset, &packet->transport.udp)) {
                    packet->has_transport = true;
                    packet->transport_proto = PROTO_UDP;
                    offset += 8;
                }
                break;
            }
            case IP_PROTO_ICMPV6: {
                if (parse_icmp(data + offset, length - offset, &packet->transport.icmp)) {
                    packet->has_transport = true;
                    packet->transport_proto = PROTO_ICMPV6;
                    offset += 8;
                }
                break;
            }
        }
        
        /* Extract payload for IPv6 */
        if (offset < length) {
            packet->payload = (uint8_t*)(data + offset);
            packet->payload_length = length - offset;
        }
    }
    
    return true;
}

/* Calculate flow hash from 5-tuple */
uint64_t netguard_flow_hash(uint32_t src_ip, uint32_t dst_ip, 
                            uint16_t src_port, uint16_t dst_port, 
                            uint8_t protocol) {
    /* Normalize direction for bidirectional flow tracking */
    uint32_t ip1, ip2;
    uint16_t port1, port2;
    
    if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
        ip1 = src_ip;
        ip2 = dst_ip;
        port1 = src_port;
        port2 = dst_port;
    } else {
        ip1 = dst_ip;
        ip2 = src_ip;
        port1 = dst_port;
        port2 = src_port;
    }
    
    /* FNV-1a hash */
    uint64_t hash = 0xcbf29ce484222325ULL;
    uint8_t* bytes;
    
    bytes = (uint8_t*)&ip1;
    for (int i = 0; i < 4; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    
    bytes = (uint8_t*)&ip2;
    for (int i = 0; i < 4; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    
    bytes = (uint8_t*)&port1;
    for (int i = 0; i < 2; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    
    bytes = (uint8_t*)&port2;
    for (int i = 0; i < 2; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    
    hash ^= protocol;
    hash *= 0x100000001b3ULL;
    
    return hash;
}
