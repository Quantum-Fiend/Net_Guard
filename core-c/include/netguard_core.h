/*
 * Net_Guard - High-Performance Hybrid Intrusion Detection System
 * Copyright (c) 2024 Net_Guard Project
 * 
 * Core Header - Public API Declarations
 */

#ifndef NETGUARD_CORE_H
#define NETGUARD_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* =============================================================================
 * Platform-specific exports
 * ============================================================================= */
#ifdef _WIN32
    #ifdef NETGUARD_EXPORTS
        #define NETGUARD_API __declspec(dllexport)
    #else
        #define NETGUARD_API __declspec(dllimport)
    #endif
#else
    #define NETGUARD_API __attribute__((visibility("default")))
#endif

/* =============================================================================
 * Constants
 * ============================================================================= */
#define NETGUARD_VERSION_MAJOR 1
#define NETGUARD_VERSION_MINOR 0
#define NETGUARD_VERSION_PATCH 0

#define MAX_PACKET_SIZE         65535
#define MAX_PAYLOAD_SIZE        16384
#define MAX_DEVICES             32
#define MAX_DEVICE_NAME         256
#define MAX_DEVICE_DESC         512
#define MAX_RULE_NAME           128
#define MAX_PATTERN_SIZE        1024
#define MAX_FLOWS               65536
#define RING_BUFFER_SIZE        8192
#define MEMORY_POOL_BLOCK_SIZE  2048
#define MEMORY_POOL_BLOCKS      4096

/* Flow timeout in seconds */
#define FLOW_TIMEOUT_TCP        120
#define FLOW_TIMEOUT_UDP        30
#define FLOW_TIMEOUT_ICMP       10

/* Detection thresholds */
#define PORT_SCAN_THRESHOLD     20
#define PORT_SCAN_WINDOW_SEC    5
#define RATE_LIMIT_PPS          10000
#define ANOMALY_ZSCORE_THRESHOLD 3.0

/* =============================================================================
 * Enumerations
 * ============================================================================= */

/* Error codes */
typedef enum {
    NETGUARD_OK = 0,
    NETGUARD_ERROR_INIT = -1,
    NETGUARD_ERROR_NO_DEVICES = -2,
    NETGUARD_ERROR_OPEN_DEVICE = -3,
    NETGUARD_ERROR_FILTER = -4,
    NETGUARD_ERROR_MEMORY = -5,
    NETGUARD_ERROR_INVALID_PARAM = -6,
    NETGUARD_ERROR_NOT_RUNNING = -7,
    NETGUARD_ERROR_ALREADY_RUNNING = -8
} NetGuardError;

/* Protocol types */
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ETHERNET = 1,
    PROTO_IPV4 = 2,
    PROTO_IPV6 = 3,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMP = 1,
    PROTO_ICMPV6 = 58,
    PROTO_ARP = 0x0806,
    PROTO_TLS = 443
} ProtocolType;

/* Alert severity levels */
typedef enum {
    SEVERITY_INFO = 0,
    SEVERITY_LOW = 1,
    SEVERITY_MEDIUM = 2,
    SEVERITY_HIGH = 3,
    SEVERITY_CRITICAL = 4
} AlertSeverity;

/* Attack types */
typedef enum {
    ATTACK_NONE = 0,
    ATTACK_PORT_SCAN_SYN = 1,
    ATTACK_PORT_SCAN_FIN = 2,
    ATTACK_PORT_SCAN_NULL = 3,
    ATTACK_PORT_SCAN_XMAS = 4,
    ATTACK_PORT_SCAN_UDP = 5,
    ATTACK_DOS_SYN_FLOOD = 10,
    ATTACK_DOS_UDP_FLOOD = 11,
    ATTACK_DOS_ICMP_FLOOD = 12,
    ATTACK_SIGNATURE_MATCH = 20,
    ATTACK_ANOMALY_RATE = 30,
    ATTACK_ANOMALY_ENTROPY = 31,
    ATTACK_ANOMALY_BEHAVIOR = 32,
    ATTACK_TLS_SUSPICIOUS = 40,
    ATTACK_DATA_EXFIL = 50
} AttackType;

/* Flow state */
typedef enum {
    FLOW_STATE_NEW = 0,
    FLOW_STATE_ESTABLISHED = 1,
    FLOW_STATE_FIN_WAIT = 2,
    FLOW_STATE_CLOSE_WAIT = 3,
    FLOW_STATE_CLOSED = 4,
    FLOW_STATE_TIMEOUT = 5
} FlowState;

/* TCP flags */
typedef enum {
    TCP_FLAG_FIN = 0x01,
    TCP_FLAG_SYN = 0x02,
    TCP_FLAG_RST = 0x04,
    TCP_FLAG_PSH = 0x08,
    TCP_FLAG_ACK = 0x10,
    TCP_FLAG_URG = 0x20,
    TCP_FLAG_ECE = 0x40,
    TCP_FLAG_CWR = 0x80
} TcpFlags;

/* =============================================================================
 * Data Structures
 * ============================================================================= */

/* Network device information */
typedef struct {
    char name[MAX_DEVICE_NAME];
    char description[MAX_DEVICE_DESC];
    uint32_t ip_address;
    uint32_t netmask;
    uint8_t mac_address[6];
    bool is_loopback;
    bool is_up;
} NetDevice;

/* Ethernet header */
typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} EthernetHeader;

/* IPv4 header */
typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IPv4Header;

/* IPv6 header */
typedef struct {
    uint32_t version_class_flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
} IPv6Header;

/* TCP header */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCPHeader;

/* UDP header */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UDPHeader;

/* ICMP header */
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
} ICMPHeader;

/* Parsed packet structure */
typedef struct {
    /* Capture metadata */
    uint64_t timestamp_us;
    uint32_t capture_length;
    uint32_t wire_length;
    
    /* Layer 2 */
    EthernetHeader eth;
    bool has_eth;
    
    /* Layer 3 */
    union {
        IPv4Header ipv4;
        IPv6Header ipv6;
    } ip;
    bool is_ipv6;
    bool has_ip;
    
    /* Layer 4 */
    union {
        TCPHeader tcp;
        UDPHeader udp;
        ICMPHeader icmp;
    } transport;
    ProtocolType transport_proto;
    bool has_transport;
    
    /* Payload */
    uint8_t* payload;
    uint32_t payload_length;
    
    /* Flow identification */
    uint64_t flow_hash;
    
    /* Raw packet data */
    uint8_t* raw_data;
    uint32_t raw_length;
} ParsedPacket;

/* Flow record */
typedef struct {
    /* 5-tuple */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    /* State */
    FlowState state;
    uint64_t first_seen;
    uint64_t last_seen;
    
    /* Statistics */
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    
    /* TCP-specific */
    uint32_t tcp_flags_seen;
    bool syn_seen;
    bool syn_ack_seen;
    bool fin_seen;
    
    /* Hash for lookup */
    uint64_t flow_hash;
} FlowRecord;

/* Alert structure */
typedef struct {
    uint64_t timestamp;
    AttackType attack_type;
    AlertSeverity severity;
    
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    char description[256];
    char rule_name[MAX_RULE_NAME];
    
    /* Packet snapshot */
    uint8_t packet_snapshot[256];
    uint32_t snapshot_length;
    
    /* Detection details */
    double confidence;
    uint32_t unique_ports;
    double entropy;
} Alert;

/* Detection rule */
typedef struct {
    char name[MAX_RULE_NAME];
    char pattern[MAX_PATTERN_SIZE];
    uint32_t pattern_length;
    
    ProtocolType protocol;
    uint16_t port;
    bool any_port;
    
    AlertSeverity severity;
    AttackType attack_type;
    
    bool enabled;
    bool regex;
} DetectionRule;

/* Statistics */
typedef struct {
    /* Packet counts */
    uint64_t packets_captured;
    uint64_t packets_dropped;
    uint64_t packets_processed;
    
    /* Byte counts */
    uint64_t bytes_captured;
    
    /* Protocol breakdown */
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;
    
    /* Detection stats */
    uint64_t alerts_generated;
    uint64_t port_scans_detected;
    uint64_t signatures_matched;
    uint64_t anomalies_detected;
    
    /* Flow stats */
    uint32_t active_flows;
    uint64_t total_flows;
    
    /* Performance */
    double packets_per_second;
    double bytes_per_second;
    uint64_t start_time;
    uint64_t uptime_seconds;
    
    /* Memory */
    size_t memory_used;
    size_t memory_pool_used;
    size_t ring_buffer_usage;
} CaptureStats;

/* Port scan tracker */
typedef struct {
    uint32_t src_ip;
    uint16_t* ports;
    uint32_t port_count;
    uint32_t port_capacity;
    uint64_t first_seen;
    uint64_t last_seen;
    uint8_t scan_type;  /* Based on TCP flags */
} PortScanTracker;

/* TLS fingerprint */
typedef struct {
    char ja3_hash[33];      /* MD5 hash as hex string */
    char ja3s_hash[33];
    uint16_t tls_version;
    uint16_t* cipher_suites;
    uint32_t cipher_count;
    uint16_t* extensions;
    uint32_t extension_count;
    bool is_suspicious;
} TLSFingerprint;

/* Anomaly baseline */
typedef struct {
    double pps_mean;
    double pps_stddev;
    double bps_mean;
    double bps_stddev;
    double flow_duration_mean;
    double flow_duration_stddev;
    uint64_t sample_count;
    bool is_trained;
} AnomalyBaseline;

/* =============================================================================
 * Callback Types
 * ============================================================================= */

/* Packet callback - called for each captured packet */
typedef void (*PacketCallback)(const ParsedPacket* packet, void* user_data);

/* Alert callback - called when an attack is detected */
typedef void (*AlertCallback)(const Alert* alert, void* user_data);

/* Statistics callback - called periodically with stats */
typedef void (*StatsCallback)(const CaptureStats* stats, void* user_data);

/* Flow callback - called on flow state changes */
typedef void (*FlowCallback)(const FlowRecord* flow, bool is_new, void* user_data);

/* =============================================================================
 * Capture Engine API
 * ============================================================================= */

/* Initialize the capture engine */
NETGUARD_API NetGuardError netguard_init(void);

/* Shutdown the capture engine */
NETGUARD_API void netguard_shutdown(void);

/* Get list of available network devices */
NETGUARD_API NetGuardError netguard_get_devices(NetDevice* devices, uint32_t* count);

/* Start packet capture on a device */
NETGUARD_API NetGuardError netguard_start_capture(const char* device_name, const char* bpf_filter);

/* Stop packet capture */
NETGUARD_API NetGuardError netguard_stop_capture(void);

/* Start PCAP dump to file */
NETGUARD_API NetGuardError netguard_start_pcap(const char* filepath);

/* Stop PCAP dump */
NETGUARD_API NetGuardError netguard_stop_pcap(void);

/* Check if capture is running */
NETGUARD_API bool netguard_is_running(void);

/* Set promiscuous mode */
NETGUARD_API NetGuardError netguard_set_promiscuous(bool enabled);

/* Get current statistics */
NETGUARD_API NetGuardError netguard_get_stats(CaptureStats* stats);

/* =============================================================================
 * Callback Registration
 * ============================================================================= */

NETGUARD_API void netguard_set_packet_callback(PacketCallback callback, void* user_data);
NETGUARD_API void netguard_set_alert_callback(AlertCallback callback, void* user_data);
NETGUARD_API void netguard_set_stats_callback(StatsCallback callback, void* user_data);
NETGUARD_API void netguard_set_flow_callback(FlowCallback callback, void* user_data);

/* =============================================================================
 * Detection Engine API
 * ============================================================================= */

/* Enable/disable detection modules */
NETGUARD_API void netguard_enable_port_scan_detection(bool enabled);
NETGUARD_API void netguard_enable_signature_detection(bool enabled);
NETGUARD_API void netguard_enable_anomaly_detection(bool enabled);
NETGUARD_API void netguard_enable_tls_fingerprinting(bool enabled);

/* Configure detection thresholds */
NETGUARD_API void netguard_set_port_scan_threshold(uint32_t unique_ports, uint32_t window_seconds);
NETGUARD_API void netguard_set_rate_limit(uint32_t packets_per_second);
NETGUARD_API void netguard_set_anomaly_threshold(double z_score);

/* Rule management */
NETGUARD_API NetGuardError netguard_add_rule(const DetectionRule* rule);
NETGUARD_API NetGuardError netguard_remove_rule(const char* rule_name);
NETGUARD_API NetGuardError netguard_clear_rules(void);
NETGUARD_API uint32_t netguard_get_rule_count(void);

/* Load rules from JSON file */
NETGUARD_API NetGuardError netguard_load_rules_json(const char* file_path);

/* =============================================================================
 * Flow Tracking API
 * ============================================================================= */

/* Get active flows */
NETGUARD_API NetGuardError netguard_get_flows(FlowRecord* flows, uint32_t* count, uint32_t max_count);

/* Get flow by hash */
NETGUARD_API NetGuardError netguard_get_flow(uint64_t flow_hash, FlowRecord* flow);

/* Clear expired flows */
NETGUARD_API void netguard_cleanup_flows(void);

/* =============================================================================
 * TLS Fingerprinting API
 * ============================================================================= */

/* Get JA3 hash for a flow */
NETGUARD_API NetGuardError netguard_get_ja3(uint64_t flow_hash, TLSFingerprint* fingerprint);

/* Check if JA3 hash is in blocklist */
NETGUARD_API bool netguard_is_ja3_blocked(const char* ja3_hash);

/* Add JA3 hash to blocklist */
NETGUARD_API NetGuardError netguard_block_ja3(const char* ja3_hash, const char* description);

/* =============================================================================
 * Anomaly Detection API
 * ============================================================================= */

/* Start baseline training */
NETGUARD_API NetGuardError netguard_train_baseline(uint32_t duration_seconds);

/* Check if baseline is trained */
NETGUARD_API bool netguard_baseline_ready(void);

/* Get current anomaly score */
NETGUARD_API double netguard_get_anomaly_score(void);

/* Get baseline statistics */
NETGUARD_API NetGuardError netguard_get_baseline(AnomalyBaseline* baseline);

/* =============================================================================
 * Utility Functions
 * ============================================================================= */

/* Convert IP address to string */
NETGUARD_API const char* netguard_ip_to_string(uint32_t ip);

/* Convert MAC address to string */
NETGUARD_API const char* netguard_mac_to_string(const uint8_t* mac);

/* Get protocol name */
NETGUARD_API const char* netguard_protocol_name(ProtocolType proto);

/* Get attack type name */
NETGUARD_API const char* netguard_attack_name(AttackType attack);

/* Get severity name */
NETGUARD_API const char* netguard_severity_name(AlertSeverity severity);

/* Get version string */
NETGUARD_API const char* netguard_version(void);

/* Get last error message */
NETGUARD_API const char* netguard_get_error(void);

/* Calculate entropy of data */
NETGUARD_API double netguard_calculate_entropy(const uint8_t* data, uint32_t length);

/* Calculate flow hash */
NETGUARD_API uint64_t netguard_flow_hash(uint32_t src_ip, uint32_t dst_ip, 
                                          uint16_t src_port, uint16_t dst_port, 
                                          uint8_t protocol);

#ifdef __cplusplus
}
#endif

#endif /* NETGUARD_CORE_H */
