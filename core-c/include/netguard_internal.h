/*
 * Net_Guard - High-Performance Hybrid Intrusion Detection System
 * Internal Header - Private declarations and utilities
 */

#ifndef NETGUARD_INTERNAL_H
#define NETGUARD_INTERNAL_H

#include "netguard_core.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "wpcap.lib")
    
    /* Thread primitives */
    typedef HANDLE ng_thread_t;
    typedef CRITICAL_SECTION ng_mutex_t;
    typedef CONDITION_VARIABLE ng_cond_t;
    
    #define ng_mutex_init(m) InitializeCriticalSection(m)
    #define ng_mutex_destroy(m) DeleteCriticalSection(m)
    #define ng_mutex_lock(m) EnterCriticalSection(m)
    #define ng_mutex_unlock(m) LeaveCriticalSection(m)
    
    #define ng_cond_init(c) InitializeConditionVariable(c)
    #define ng_cond_signal(c) WakeConditionVariable(c)
    #define ng_cond_broadcast(c) WakeAllConditionVariable(c)
    #define ng_cond_wait(c, m) SleepConditionVariableCS(c, m, INFINITE)
    
    #define ng_atomic_inc(v) InterlockedIncrement((volatile LONG*)(v))
    #define ng_atomic_dec(v) InterlockedDecrement((volatile LONG*)(v))
    #define ng_atomic_add(v, n) InterlockedAdd((volatile LONG*)(v), (LONG)(n))
    #define ng_atomic_load(v) InterlockedCompareExchange((volatile LONG*)(v), 0, 0)
    
    #define ng_sleep_ms(ms) Sleep(ms)
    #define ng_get_time_us() (GetTickCount64() * 1000ULL)
#else
    #include <pthread.h>
    #include <unistd.h>
    #include <sys/time.h>
    #include <arpa/inet.h>
    
    typedef pthread_t ng_thread_t;
    typedef pthread_mutex_t ng_mutex_t;
    typedef pthread_cond_t ng_cond_t;
    
    #define ng_mutex_init(m) pthread_mutex_init(m, NULL)
    #define ng_mutex_destroy(m) pthread_mutex_destroy(m)
    #define ng_mutex_lock(m) pthread_mutex_lock(m)
    #define ng_mutex_unlock(m) pthread_mutex_unlock(m)
    
    #define ng_cond_init(c) pthread_cond_init(c, NULL)
    #define ng_cond_signal(c) pthread_cond_signal(c)
    #define ng_cond_broadcast(c) pthread_cond_broadcast(c)
    #define ng_cond_wait(c, m) pthread_cond_wait(c, m)
    
    #define ng_atomic_inc(v) __sync_add_and_fetch(v, 1)
    #define ng_atomic_dec(v) __sync_sub_and_fetch(v, 1)
    #define ng_atomic_add(v, n) __sync_add_and_fetch(v, n)
    #define ng_atomic_load(v) __sync_val_compare_and_swap(v, 0, 0)
    
    #define ng_sleep_ms(ms) usleep((ms) * 1000)
    
    static inline uint64_t ng_get_time_us(void) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
    }
#endif

/* Pcap includes */
#include <pcap.h>

/* =============================================================================
 * Ring Buffer
 * ============================================================================= */

typedef struct {
    ParsedPacket* packets;
    volatile uint32_t head;
    volatile uint32_t tail;
    uint32_t capacity;
    uint32_t mask;
    ng_mutex_t mutex;
    ng_cond_t not_empty;
    ng_cond_t not_full;
} RingBuffer;

RingBuffer* ring_buffer_create(uint32_t capacity);
void ring_buffer_destroy(RingBuffer* rb);
bool ring_buffer_push(RingBuffer* rb, const ParsedPacket* packet);
bool ring_buffer_pop(RingBuffer* rb, ParsedPacket* packet);
uint32_t ring_buffer_size(RingBuffer* rb);
bool ring_buffer_is_empty(RingBuffer* rb);
bool ring_buffer_is_full(RingBuffer* rb);

/* =============================================================================
 * Memory Pool
 * ============================================================================= */

typedef struct MemoryBlock {
    struct MemoryBlock* next;
} MemoryBlock;

typedef struct {
    uint8_t* memory;
    MemoryBlock* free_list;
    size_t block_size;
    size_t block_count;
    size_t used_blocks;
    ng_mutex_t mutex;
} MemoryPool;

MemoryPool* memory_pool_create(size_t block_size, size_t block_count);
void memory_pool_destroy(MemoryPool* pool);
void* memory_pool_alloc(MemoryPool* pool);
void memory_pool_free(MemoryPool* pool, void* ptr);
size_t memory_pool_used(MemoryPool* pool);

/* =============================================================================
 * Flow Table
 * ============================================================================= */

#define FLOW_TABLE_SIZE 65536

typedef struct FlowEntry {
    FlowRecord flow;
    struct FlowEntry* next;
} FlowEntry;

typedef struct {
    FlowEntry** buckets;
    uint32_t size;
    uint32_t count;
    ng_mutex_t mutex;
    MemoryPool* entry_pool;
} FlowTable;

FlowTable* flow_table_create(void);
void flow_table_destroy(FlowTable* table);
FlowRecord* flow_table_lookup(FlowTable* table, uint64_t hash);
FlowRecord* flow_table_insert(FlowTable* table, const FlowRecord* flow);
void flow_table_remove(FlowTable* table, uint64_t hash);
void flow_table_cleanup(FlowTable* table, uint64_t timeout_us);
uint32_t flow_table_count(FlowTable* table);

/* =============================================================================
 * Port Scan Tracker
 * ============================================================================= */

#define PORT_SCAN_TABLE_SIZE 4096

typedef struct PortScanEntry {
    PortScanTracker tracker;
    struct PortScanEntry* next;
} PortScanEntry;

typedef struct {
    PortScanEntry** buckets;
    uint32_t size;
    ng_mutex_t mutex;
    uint32_t threshold_ports;
    uint32_t window_seconds;
} PortScanTable;

PortScanTable* port_scan_table_create(void);
void port_scan_table_destroy(PortScanTable* table);
bool port_scan_check(PortScanTable* table, uint32_t src_ip, uint16_t dst_port, uint8_t tcp_flags, AttackType* scan_type);
void port_scan_cleanup(PortScanTable* table, uint64_t current_time);

/* =============================================================================
 * Signature Engine
 * ============================================================================= */

#define MAX_SIGNATURES 1024

typedef struct {
    DetectionRule rules[MAX_SIGNATURES];
    uint32_t count;
    ng_mutex_t mutex;
    
    /* Boyer-Moore precomputed tables */
    int* bad_char_tables[MAX_SIGNATURES];
    int* good_suffix_tables[MAX_SIGNATURES];
} SignatureEngine;

SignatureEngine* signature_engine_create(void);
void signature_engine_destroy(SignatureEngine* engine);
bool signature_engine_add(SignatureEngine* engine, const DetectionRule* rule);
bool signature_engine_remove(SignatureEngine* engine, const char* name);
void signature_engine_clear(SignatureEngine* engine);
bool signature_engine_match(SignatureEngine* engine, const ParsedPacket* packet, DetectionRule* matched_rule);

/* =============================================================================
 * Anomaly Detector
 * ============================================================================= */

typedef struct {
    /* Baseline */
    AnomalyBaseline baseline;
    bool training;
    uint64_t training_start;
    uint32_t training_duration;
    
    /* Real-time stats */
    double current_pps;
    double current_bps;
    uint64_t last_update;
    
    /* Rolling window */
    double* pps_samples;
    double* bps_samples;
    uint32_t sample_index;
    uint32_t sample_count;
    uint32_t sample_capacity;
    
    ng_mutex_t mutex;
} AnomalyDetector;

AnomalyDetector* anomaly_detector_create(void);
void anomaly_detector_destroy(AnomalyDetector* detector);
void anomaly_detector_update(AnomalyDetector* detector, uint64_t packets, uint64_t bytes, uint64_t time_us);
double anomaly_detector_score(AnomalyDetector* detector);
void anomaly_detector_train(AnomalyDetector* detector, uint32_t duration_seconds);
bool anomaly_detector_is_ready(AnomalyDetector* detector);

/* =============================================================================
 * TLS Fingerprinter
 * ============================================================================= */

typedef struct {
    char** blocked_hashes;
    char** blocked_descriptions;
    uint32_t blocked_count;
    uint32_t blocked_capacity;
    ng_mutex_t mutex;
} TLSFingerprinter;

TLSFingerprinter* tls_fingerprinter_create(void);
void tls_fingerprinter_destroy(TLSFingerprinter* fp);
bool tls_parse_client_hello(const uint8_t* data, uint32_t length, TLSFingerprint* fp);
void tls_compute_ja3(TLSFingerprint* fp);
bool tls_is_blocked(TLSFingerprinter* fp, const char* ja3_hash);
void tls_block_hash(TLSFingerprinter* fp, const char* ja3_hash, const char* description);

/* =============================================================================
 * Global Engine State
 * ============================================================================= */

typedef struct {
    /* Capture state */
    bool initialized;
    bool running;
    pcap_t* pcap_handle;
    char device_name[MAX_DEVICE_NAME];
    
    /* Threads */
    ng_thread_t capture_thread;
    ng_thread_t processor_thread;
    ng_thread_t stats_thread;
    
    /* Data structures */
    RingBuffer* packet_buffer;
    MemoryPool* packet_pool;
    FlowTable* flow_table;
    PortScanTable* port_scan_table;
    SignatureEngine* signature_engine;
    AnomalyDetector* anomaly_detector;
    TLSFingerprinter* tls_fingerprinter;
    
    /* Callbacks */
    PacketCallback packet_callback;
    void* packet_callback_data;
    AlertCallback alert_callback;
    void* alert_callback_data;
    StatsCallback stats_callback;
    void* stats_callback_data;
    FlowCallback flow_callback;
    void* flow_callback_data;
    
    /* Detection flags */
    bool detect_port_scans;
    bool detect_signatures;
    bool detect_anomalies;
    bool detect_tls;
    
    /* Statistics */
    CaptureStats stats;
    ng_mutex_t stats_mutex;
    
    /* Error handling */
    char last_error[512];
    ng_mutex_t error_mutex;
    
    /* Settings */
    bool promiscuous;
    uint32_t port_scan_threshold;
    uint32_t port_scan_window;
    uint32_t rate_limit;
    double anomaly_threshold;
    
    /* PCAP Dumping */
    pcap_dumper_t* pcap_dumper;
} EngineState;

/* Global engine instance */
extern EngineState g_engine;

/* =============================================================================
 * Protocol Parsing
 * ============================================================================= */

bool parse_ethernet(const uint8_t* data, uint32_t length, EthernetHeader* eth);
bool parse_ipv4(const uint8_t* data, uint32_t length, IPv4Header* ip, uint32_t* header_len);
bool parse_ipv6(const uint8_t* data, uint32_t length, IPv6Header* ip);
bool parse_tcp(const uint8_t* data, uint32_t length, TCPHeader* tcp, uint32_t* header_len);
bool parse_udp(const uint8_t* data, uint32_t length, UDPHeader* udp);
bool parse_icmp(const uint8_t* data, uint32_t length, ICMPHeader* icmp);
bool parse_packet(const uint8_t* data, uint32_t length, uint64_t timestamp, ParsedPacket* packet);

/* =============================================================================
 * Utility Functions
 * ============================================================================= */

void set_error(const char* format, ...);
uint64_t current_time_us(void);
uint32_t hash32(uint32_t a);
uint64_t hash64(uint64_t a);
double calculate_entropy(const uint8_t* data, uint32_t length);
void generate_alert(AttackType type, AlertSeverity severity, const ParsedPacket* packet, const char* description);

/* String conversion buffers (thread-local) */
#ifdef _WIN32
    __declspec(thread) extern char ip_string_buffer[64];
    __declspec(thread) extern char mac_string_buffer[32];
#else
    extern __thread char ip_string_buffer[64];
    extern __thread char mac_string_buffer[32];
#endif

#endif /* NETGUARD_INTERNAL_H */
