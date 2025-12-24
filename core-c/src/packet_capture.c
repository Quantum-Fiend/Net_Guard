/*
 * Net_Guard - Packet Capture Engine
 * Npcap integration for live network traffic capture
 */

#include "netguard_internal.h"

/* Global engine state */
EngineState g_engine = {0};

/* Thread-local string buffers */
#ifdef _WIN32
__declspec(thread) char ip_string_buffer[64];
__declspec(thread) char mac_string_buffer[32];
#else
__thread char ip_string_buffer[64];
__thread char mac_string_buffer[32];
#endif

/* =============================================================================
 * Error Handling
 * ============================================================================= */

void set_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    ng_mutex_lock(&g_engine.error_mutex);
    vsnprintf(g_engine.last_error, sizeof(g_engine.last_error), format, args);
    ng_mutex_unlock(&g_engine.error_mutex);
    
    va_end(args);
}

NETGUARD_API const char* netguard_get_error(void) {
    return g_engine.last_error;
}

/* =============================================================================
 * Utility Functions
 * ============================================================================= */

uint64_t current_time_us(void) {
    return ng_get_time_us();
}

uint32_t hash32(uint32_t a) {
    a = (a ^ 61) ^ (a >> 16);
    a = a + (a << 3);
    a = a ^ (a >> 4);
    a = a * 0x27d4eb2d;
    a = a ^ (a >> 15);
    return a;
}

uint64_t hash64(uint64_t key) {
    key = (~key) + (key << 21);
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8);
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 28);
    key = key + (key << 31);
    return key;
}

NETGUARD_API const char* netguard_ip_to_string(uint32_t ip) {
    snprintf(ip_string_buffer, sizeof(ip_string_buffer),
             "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
    return ip_string_buffer;
}

NETGUARD_API const char* netguard_mac_to_string(const uint8_t* mac) {
    snprintf(mac_string_buffer, sizeof(mac_string_buffer),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_string_buffer;
}

NETGUARD_API const char* netguard_protocol_name(ProtocolType proto) {
    switch (proto) {
        case PROTO_ETHERNET: return "Ethernet";
        case PROTO_IPV4: return "IPv4";
        case PROTO_IPV6: return "IPv6";
        case PROTO_TCP: return "TCP";
        case PROTO_UDP: return "UDP";
        case PROTO_ICMP: return "ICMP";
        case PROTO_ICMPV6: return "ICMPv6";
        case PROTO_ARP: return "ARP";
        case PROTO_TLS: return "TLS";
        default: return "Unknown";
    }
}

NETGUARD_API const char* netguard_attack_name(AttackType attack) {
    switch (attack) {
        case ATTACK_NONE: return "None";
        case ATTACK_PORT_SCAN_SYN: return "SYN Port Scan";
        case ATTACK_PORT_SCAN_FIN: return "FIN Port Scan";
        case ATTACK_PORT_SCAN_NULL: return "NULL Port Scan";
        case ATTACK_PORT_SCAN_XMAS: return "XMAS Port Scan";
        case ATTACK_PORT_SCAN_UDP: return "UDP Port Scan";
        case ATTACK_DOS_SYN_FLOOD: return "SYN Flood";
        case ATTACK_DOS_UDP_FLOOD: return "UDP Flood";
        case ATTACK_DOS_ICMP_FLOOD: return "ICMP Flood";
        case ATTACK_SIGNATURE_MATCH: return "Signature Match";
        case ATTACK_ANOMALY_RATE: return "Rate Anomaly";
        case ATTACK_ANOMALY_ENTROPY: return "Entropy Anomaly";
        case ATTACK_ANOMALY_BEHAVIOR: return "Behavioral Anomaly";
        case ATTACK_TLS_SUSPICIOUS: return "Suspicious TLS";
        case ATTACK_DATA_EXFIL: return "Data Exfiltration";
        default: return "Unknown";
    }
}

NETGUARD_API const char* netguard_severity_name(AlertSeverity severity) {
    switch (severity) {
        case SEVERITY_INFO: return "INFO";
        case SEVERITY_LOW: return "LOW";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

NETGUARD_API const char* netguard_version(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d",
             NETGUARD_VERSION_MAJOR,
             NETGUARD_VERSION_MINOR,
             NETGUARD_VERSION_PATCH);
    return version;
}

/* =============================================================================
 * Packet Processing
 * ============================================================================= */

/* Process a captured packet through the detection pipeline */
static void process_packet(const ParsedPacket* packet) {
    if (!packet) return;
    
    /* Update statistics */
    ng_atomic_inc(&g_engine.stats.packets_processed);
    ng_atomic_add(&g_engine.stats.bytes_captured, packet->wire_length);
    
    /* Protocol statistics */
    if (packet->has_transport) {
        switch (packet->transport_proto) {
            case PROTO_TCP:
                ng_atomic_inc(&g_engine.stats.tcp_packets);
                break;
            case PROTO_UDP:
                ng_atomic_inc(&g_engine.stats.udp_packets);
                break;
            case PROTO_ICMP:
            case PROTO_ICMPV6:
                ng_atomic_inc(&g_engine.stats.icmp_packets);
                break;
            default:
                ng_atomic_inc(&g_engine.stats.other_packets);
                break;
        }
    }
    
    /* Update flow tracking */
    if (g_engine.flow_table && packet->has_ip && packet->has_transport) {
        flow_update_from_packet(g_engine.flow_table, packet);
    }
    
    /* Detection: Port scan */
    if (g_engine.detect_port_scans && g_engine.port_scan_table && 
        packet->has_ip && packet->transport_proto == PROTO_TCP) {
        
        AttackType scan_type;
        if (port_scan_check(g_engine.port_scan_table,
                           packet->ip.ipv4.src_ip,
                           packet->transport.tcp.dst_port,
                           packet->transport.tcp.flags,
                           &scan_type)) {
            
            ng_atomic_inc(&g_engine.stats.port_scans_detected);
            
            char desc[256];
            snprintf(desc, sizeof(desc), "Port scan detected from %s: %u unique ports",
                    netguard_ip_to_string(packet->ip.ipv4.src_ip),
                    g_engine.port_scan_table->threshold_ports);
            
            generate_alert(scan_type, SEVERITY_HIGH, packet, desc);
        }
    }
    
    /* Detection: Signature matching */
    if (g_engine.detect_signatures && g_engine.signature_engine && 
        packet->payload && packet->payload_length > 0) {
        
        DetectionRule matched_rule;
        if (signature_engine_match(g_engine.signature_engine, packet, &matched_rule)) {
            ng_atomic_inc(&g_engine.stats.signatures_matched);
            generate_alert(ATTACK_SIGNATURE_MATCH, matched_rule.severity, 
                          packet, matched_rule.name);
        }
    }
    
    /* Detection: TLS fingerprinting */
    if (g_engine.detect_tls && g_engine.tls_fingerprinter &&
        packet->transport_proto == PROTO_TCP && 
        packet->payload && packet->payload_length > 43) {
        
        /* Check if this looks like TLS ClientHello */
        if (packet->payload[0] == 22 && packet->payload[5] == 1) {
            TLSFingerprint fp;
            if (tls_parse_client_hello(packet->payload, packet->payload_length, &fp)) {
                tls_compute_ja3(&fp);
                
                if (tls_is_blocked(g_engine.tls_fingerprinter, fp.ja3_hash)) {
                    char desc[256];
                    snprintf(desc, sizeof(desc), "Blocked JA3 fingerprint: %s", fp.ja3_hash);
                    generate_alert(ATTACK_TLS_SUSPICIOUS, SEVERITY_HIGH, packet, desc);
                }
                
                /* Free dynamically allocated memory in fingerprint */
                if (fp.cipher_suites) free(fp.cipher_suites);
                if (fp.extensions) free(fp.extensions);
            }
        }
    }
    
    /* User packet callback */
    if (g_engine.packet_callback) {
        g_engine.packet_callback(packet, g_engine.packet_callback_data);
    }
}

/* Pcap callback function */
static void pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* data) {
    (void)user;
    
    ng_atomic_inc(&g_engine.stats.packets_captured);
    
    ParsedPacket packet;
    uint64_t timestamp = (uint64_t)header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
    
    if (parse_packet(data, header->caplen, timestamp, &packet)) {
        /* PCAP Dump if enabled */
        if (g_engine.pcap_dumper) {
             pcap_dump((u_char*)g_engine.pcap_dumper, header, data);
        }

        /* Push to ring buffer for async processing, or process directly */
        if (g_engine.packet_buffer) {
            if (!ring_buffer_push(g_engine.packet_buffer, &packet)) {
                ng_atomic_inc(&g_engine.stats.packets_dropped);
            }
        } else {
            process_packet(&packet);
        }
    }
}

/* Capture thread function */
#ifdef _WIN32
static DWORD WINAPI capture_thread_func(LPVOID param) {
#else
static void* capture_thread_func(void* param) {
#endif
    (void)param;
    
    while (g_engine.running && g_engine.pcap_handle) {
        int result = pcap_dispatch(g_engine.pcap_handle, 100, pcap_callback, NULL);
        if (result < 0) {
            if (result == PCAP_ERROR_BREAK) {
                break;  /* pcap_breakloop called */
            }
            set_error("Capture error: %s", pcap_geterr(g_engine.pcap_handle));
            break;
        }
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* Processor thread function - consumes packets from ring buffer */
#ifdef _WIN32
static DWORD WINAPI processor_thread_func(LPVOID param) {
#else
static void* processor_thread_func(void* param) {
#endif
    (void)param;
    
    ParsedPacket packet;
    
    while (g_engine.running) {
        if (ring_buffer_pop(g_engine.packet_buffer, &packet)) {
            process_packet(&packet);
            
            /* Free any dynamically allocated raw data */
            if (packet.raw_data && packet.raw_length > 0) {
                free(packet.raw_data);
            }
        } else {
            ng_sleep_ms(1);  /* Small sleep to avoid busy waiting */
        }
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* Statistics thread function */
#ifdef _WIN32
static DWORD WINAPI stats_thread_func(LPVOID param) {
#else
static void* stats_thread_func(void* param) {
#endif
    (void)param;
    
    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
    uint64_t last_time = current_time_us();
    
    while (g_engine.running) {
        ng_sleep_ms(1000);  /* Update every second */
        
        uint64_t now = current_time_us();
        uint64_t elapsed_us = now - last_time;
        
        if (elapsed_us > 0) {
            uint64_t current_packets = g_engine.stats.packets_captured;
            uint64_t current_bytes = g_engine.stats.bytes_captured;
            
            double elapsed_sec = elapsed_us / 1000000.0;
            g_engine.stats.packets_per_second = (current_packets - last_packets) / elapsed_sec;
            g_engine.stats.bytes_per_second = (current_bytes - last_bytes) / elapsed_sec;
            g_engine.stats.uptime_seconds = (now - g_engine.stats.start_time) / 1000000;
            
            /* Update flow count */
            if (g_engine.flow_table) {
                g_engine.stats.active_flows = flow_table_count(g_engine.flow_table);
            }
            
            /* Memory stats */
            if (g_engine.packet_buffer) {
                g_engine.stats.ring_buffer_usage = ring_buffer_size(g_engine.packet_buffer);
            }
            if (g_engine.packet_pool) {
                g_engine.stats.memory_pool_used = memory_pool_used(g_engine.packet_pool);
            }
            
            /* Anomaly detection update */
            if (g_engine.anomaly_detector) {
                anomaly_detector_update(g_engine.anomaly_detector,
                                       current_packets - last_packets,
                                       current_bytes - last_bytes,
                                       now);
                
                /* Check for anomaly */
                if (g_engine.detect_anomalies && anomaly_detector_is_ready(g_engine.anomaly_detector)) {
                    double score = anomaly_detector_score(g_engine.anomaly_detector);
                    if (score > g_engine.anomaly_threshold) {
                        ng_atomic_inc(&g_engine.stats.anomalies_detected);
                        
                        char desc[256];
                        snprintf(desc, sizeof(desc), "Traffic anomaly detected: Z-score=%.2f", score);
                        generate_alert(ATTACK_ANOMALY_RATE, SEVERITY_MEDIUM, NULL, desc);
                    }
                }
            }
            
            /* Callback if set */
            if (g_engine.stats_callback) {
                g_engine.stats_callback(&g_engine.stats, g_engine.stats_callback_data);
            }
            
            /* Cleanup old flows periodically */
            if (g_engine.flow_table) {
                flow_table_cleanup(g_engine.flow_table, now);
            }
            if (g_engine.port_scan_table) {
                port_scan_cleanup(g_engine.port_scan_table, now);
            }
            
            last_packets = current_packets;
            last_bytes = current_bytes;
            last_time = now;
        }
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* =============================================================================
 * Public API
 * ============================================================================= */

NETGUARD_API NetGuardError netguard_init(void) {
    if (g_engine.initialized) {
        return NETGUARD_ERROR_ALREADY_RUNNING;
    }
    
    memset(&g_engine, 0, sizeof(EngineState));
    
    /* Initialize mutexes */
    ng_mutex_init(&g_engine.stats_mutex);
    ng_mutex_init(&g_engine.error_mutex);
    
    /* Create data structures */
    g_engine.packet_buffer = ring_buffer_create(RING_BUFFER_SIZE);
    if (!g_engine.packet_buffer) {
        set_error("Failed to create packet buffer");
        return NETGUARD_ERROR_MEMORY;
    }
    
    g_engine.packet_pool = memory_pool_create(MEMORY_POOL_BLOCK_SIZE, MEMORY_POOL_BLOCKS);
    if (!g_engine.packet_pool) {
        set_error("Failed to create memory pool");
        ring_buffer_destroy(g_engine.packet_buffer);
        return NETGUARD_ERROR_MEMORY;
    }
    
    g_engine.flow_table = flow_table_create();
    if (!g_engine.flow_table) {
        set_error("Failed to create flow table");
        memory_pool_destroy(g_engine.packet_pool);
        ring_buffer_destroy(g_engine.packet_buffer);
        return NETGUARD_ERROR_MEMORY;
    }
    
    g_engine.port_scan_table = port_scan_table_create();
    if (!g_engine.port_scan_table) {
        set_error("Failed to create port scan table");
        flow_table_destroy(g_engine.flow_table);
        memory_pool_destroy(g_engine.packet_pool);
        ring_buffer_destroy(g_engine.packet_buffer);
        return NETGUARD_ERROR_MEMORY;
    }
    
    g_engine.signature_engine = signature_engine_create();
    g_engine.anomaly_detector = anomaly_detector_create();
    g_engine.tls_fingerprinter = tls_fingerprinter_create();
    
    /* Set default detection settings */
    g_engine.detect_port_scans = true;
    g_engine.detect_signatures = true;
    g_engine.detect_anomalies = false;  /* Requires training */
    g_engine.detect_tls = true;
    
    g_engine.port_scan_threshold = PORT_SCAN_THRESHOLD;
    g_engine.port_scan_window = PORT_SCAN_WINDOW_SEC;
    g_engine.rate_limit = RATE_LIMIT_PPS;
    g_engine.anomaly_threshold = ANOMALY_ZSCORE_THRESHOLD;
    
    g_engine.initialized = true;
    
    return NETGUARD_OK;
}

NETGUARD_API void netguard_shutdown(void) {
    if (!g_engine.initialized) return;
    
    /* Stop capture if running */
    if (g_engine.running) {
        netguard_stop_capture();
    }
    
    /* Destroy data structures */
    if (g_engine.tls_fingerprinter) {
        tls_fingerprinter_destroy(g_engine.tls_fingerprinter);
    }
    if (g_engine.anomaly_detector) {
        anomaly_detector_destroy(g_engine.anomaly_detector);
    }
    if (g_engine.signature_engine) {
        signature_engine_destroy(g_engine.signature_engine);
    }
    if (g_engine.port_scan_table) {
        port_scan_table_destroy(g_engine.port_scan_table);
    }
    if (g_engine.flow_table) {
        flow_table_destroy(g_engine.flow_table);
    }
    if (g_engine.packet_pool) {
        memory_pool_destroy(g_engine.packet_pool);
    }
    if (g_engine.packet_buffer) {
        ring_buffer_destroy(g_engine.packet_buffer);
    }
    
    ng_mutex_destroy(&g_engine.stats_mutex);
    ng_mutex_destroy(&g_engine.error_mutex);
    
    memset(&g_engine, 0, sizeof(EngineState));
}

NETGUARD_API NetGuardError netguard_get_devices(NetDevice* devices, uint32_t* count) {
    if (!devices || !count) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        set_error("Failed to enumerate devices: %s", errbuf);
        return NETGUARD_ERROR_NO_DEVICES;
    }
    
    uint32_t i = 0;
    for (pcap_if_t* d = alldevs; d != NULL && i < *count; d = d->next, i++) {
        memset(&devices[i], 0, sizeof(NetDevice));
        
        strncpy(devices[i].name, d->name, MAX_DEVICE_NAME - 1);
        if (d->description) {
            strncpy(devices[i].description, d->description, MAX_DEVICE_DESC - 1);
        }
        
        devices[i].is_loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
        devices[i].is_up = (d->flags & PCAP_IF_UP) != 0;
        
        /* Get IP address */
        for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                devices[i].ip_address = ntohl(sin->sin_addr.s_addr);
                
                if (a->netmask) {
                    struct sockaddr_in* mask = (struct sockaddr_in*)a->netmask;
                    devices[i].netmask = ntohl(mask->sin_addr.s_addr);
                }
                break;
            }
        }
    }
    
    *count = i;
    pcap_freealldevs(alldevs);
    
    if (i == 0) {
        return NETGUARD_ERROR_NO_DEVICES;
    }
    
    return NETGUARD_OK;
}

NETGUARD_API NetGuardError netguard_start_capture(const char* device_name, const char* bpf_filter) {
    if (!g_engine.initialized) {
        return NETGUARD_ERROR_INIT;
    }
    
    if (g_engine.running) {
        return NETGUARD_ERROR_ALREADY_RUNNING;
    }
    
    if (!device_name) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Open device for capture */
    g_engine.pcap_handle = pcap_open_live(
        device_name,
        MAX_PACKET_SIZE,
        g_engine.promiscuous ? 1 : 0,
        100,  /* Read timeout in ms */
        errbuf
    );
    
    if (!g_engine.pcap_handle) {
        set_error("Failed to open device: %s", errbuf);
        return NETGUARD_ERROR_OPEN_DEVICE;
    }
    
    /* Set BPF filter if provided */
    if (bpf_filter && strlen(bpf_filter) > 0) {
        struct bpf_program fp;
        if (pcap_compile(g_engine.pcap_handle, &fp, bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            set_error("Failed to compile filter: %s", pcap_geterr(g_engine.pcap_handle));
            pcap_close(g_engine.pcap_handle);
            g_engine.pcap_handle = NULL;
            return NETGUARD_ERROR_FILTER;
        }
        
        if (pcap_setfilter(g_engine.pcap_handle, &fp) == -1) {
            set_error("Failed to set filter: %s", pcap_geterr(g_engine.pcap_handle));
            pcap_freecode(&fp);
            pcap_close(g_engine.pcap_handle);
            g_engine.pcap_handle = NULL;
            return NETGUARD_ERROR_FILTER;
        }
        
        pcap_freecode(&fp);
    }
    
    strncpy(g_engine.device_name, device_name, MAX_DEVICE_NAME - 1);
    
    /* Reset statistics */
    memset(&g_engine.stats, 0, sizeof(CaptureStats));
    g_engine.stats.start_time = current_time_us();
    
    /* Start threads */
    g_engine.running = true;
    
#ifdef _WIN32
    g_engine.capture_thread = CreateThread(NULL, 0, capture_thread_func, NULL, 0, NULL);
    g_engine.processor_thread = CreateThread(NULL, 0, processor_thread_func, NULL, 0, NULL);
    g_engine.stats_thread = CreateThread(NULL, 0, stats_thread_func, NULL, 0, NULL);
#else
    pthread_create(&g_engine.capture_thread, NULL, capture_thread_func, NULL);
    pthread_create(&g_engine.processor_thread, NULL, processor_thread_func, NULL);
    pthread_create(&g_engine.stats_thread, NULL, stats_thread_func, NULL);
#endif
    
    return NETGUARD_OK;
}

NETGUARD_API NetGuardError netguard_start_pcap(const char* filepath) {
    if (!g_engine.pcap_handle) {
        return NETGUARD_ERROR_NOT_RUNNING;
    }
    
    if (g_engine.pcap_dumper) {
        return NETGUARD_ERROR_ALREADY_RUNNING;
    }

    g_engine.pcap_dumper = pcap_dump_open(g_engine.pcap_handle, filepath);
    if (!g_engine.pcap_dumper) {
        set_error("Failed to open PCAP file: %s", pcap_geterr(g_engine.pcap_handle));
        return NETGUARD_ERROR_OPEN_DEVICE; // Close enough error code
    }

    return NETGUARD_OK;
}

NETGUARD_API NetGuardError netguard_stop_pcap(void) {
    if (g_engine.pcap_dumper) {
        pcap_dump_close(g_engine.pcap_dumper);
        g_engine.pcap_dumper = NULL;
    }
    return NETGUARD_OK;
}

NETGUARD_API NetGuardError netguard_stop_capture(void) {
    if (!g_engine.running) {
        return NETGUARD_ERROR_NOT_RUNNING;
    }
    
    g_engine.running = false;
    
    /* Break pcap loop */
    if (g_engine.pcap_handle) {
        pcap_breakloop(g_engine.pcap_handle);
    }
    
    /* Wait for threads */
#ifdef _WIN32
    if (g_engine.capture_thread) {
        WaitForSingleObject(g_engine.capture_thread, 5000);
        CloseHandle(g_engine.capture_thread);
    }
    if (g_engine.processor_thread) {
        WaitForSingleObject(g_engine.processor_thread, 5000);
        CloseHandle(g_engine.processor_thread);
    }
    if (g_engine.stats_thread) {
        WaitForSingleObject(g_engine.stats_thread, 5000);
        CloseHandle(g_engine.stats_thread);
    }
#else
    if (g_engine.capture_thread) {
        pthread_join(g_engine.capture_thread, NULL);
    }
    if (g_engine.processor_thread) {
        pthread_join(g_engine.processor_thread, NULL);
    }
    if (g_engine.stats_thread) {
        pthread_join(g_engine.stats_thread, NULL);
    }
#endif
    
    /* Close pcap */
    if (g_engine.pcap_handle) {
        pcap_close(g_engine.pcap_handle);
        g_engine.pcap_handle = NULL;
    }
    
    return NETGUARD_OK;
}

NETGUARD_API bool netguard_is_running(void) {
    return g_engine.running;
}

NETGUARD_API NetGuardError netguard_set_promiscuous(bool enabled) {
    g_engine.promiscuous = enabled;
    return NETGUARD_OK;
}

NETGUARD_API NetGuardError netguard_get_stats(CaptureStats* stats) {
    if (!stats) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    ng_mutex_lock(&g_engine.stats_mutex);
    memcpy(stats, &g_engine.stats, sizeof(CaptureStats));
    ng_mutex_unlock(&g_engine.stats_mutex);
    
    return NETGUARD_OK;
}

/* Callback registration */
NETGUARD_API void netguard_set_packet_callback(PacketCallback callback, void* user_data) {
    g_engine.packet_callback = callback;
    g_engine.packet_callback_data = user_data;
}

NETGUARD_API void netguard_set_alert_callback(AlertCallback callback, void* user_data) {
    g_engine.alert_callback = callback;
    g_engine.alert_callback_data = user_data;
}

NETGUARD_API void netguard_set_stats_callback(StatsCallback callback, void* user_data) {
    g_engine.stats_callback = callback;
    g_engine.stats_callback_data = user_data;
}

NETGUARD_API void netguard_set_flow_callback(FlowCallback callback, void* user_data) {
    g_engine.flow_callback = callback;
    g_engine.flow_callback_data = user_data;
}

/* Detection enable/disable */
NETGUARD_API void netguard_enable_port_scan_detection(bool enabled) {
    g_engine.detect_port_scans = enabled;
}

NETGUARD_API void netguard_enable_signature_detection(bool enabled) {
    g_engine.detect_signatures = enabled;
}

NETGUARD_API void netguard_enable_anomaly_detection(bool enabled) {
    g_engine.detect_anomalies = enabled;
}

NETGUARD_API void netguard_enable_tls_fingerprinting(bool enabled) {
    g_engine.detect_tls = enabled;
}

/* Detection configuration */
NETGUARD_API void netguard_set_port_scan_threshold(uint32_t unique_ports, uint32_t window_seconds) {
    g_engine.port_scan_threshold = unique_ports;
    g_engine.port_scan_window = window_seconds;
    
    if (g_engine.port_scan_table) {
        g_engine.port_scan_table->threshold_ports = unique_ports;
        g_engine.port_scan_table->window_seconds = window_seconds;
    }
}

NETGUARD_API void netguard_set_rate_limit(uint32_t packets_per_second) {
    g_engine.rate_limit = packets_per_second;
}

NETGUARD_API void netguard_set_anomaly_threshold(double z_score) {
    g_engine.anomaly_threshold = z_score;
}

/* Rule management */
NETGUARD_API NetGuardError netguard_add_rule(const DetectionRule* rule) {
    if (!g_engine.signature_engine || !rule) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    if (!signature_engine_add(g_engine.signature_engine, rule)) {
        return NETGUARD_ERROR_MEMORY;
    }
    
    return NETGUARD_OK;
}

NETGUARD_API NetGuardError netguard_remove_rule(const char* rule_name) {
    if (!g_engine.signature_engine || !rule_name) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    if (!signature_engine_remove(g_engine.signature_engine, rule_name)) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    return NETGUARD_OK;
}

NETGUARD_API NetGuardError netguard_clear_rules(void) {
    if (!g_engine.signature_engine) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    signature_engine_clear(g_engine.signature_engine);
    return NETGUARD_OK;
}

NETGUARD_API uint32_t netguard_get_rule_count(void) {
    if (!g_engine.signature_engine) return 0;
    return g_engine.signature_engine->count;
}

/* Anomaly detection API */
NETGUARD_API NetGuardError netguard_train_baseline(uint32_t duration_seconds) {
    if (!g_engine.anomaly_detector) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    anomaly_detector_train(g_engine.anomaly_detector, duration_seconds);
    return NETGUARD_OK;
}

NETGUARD_API bool netguard_baseline_ready(void) {
    if (!g_engine.anomaly_detector) return false;
    return anomaly_detector_is_ready(g_engine.anomaly_detector);
}

NETGUARD_API double netguard_get_anomaly_score(void) {
    if (!g_engine.anomaly_detector) return 0.0;
    return anomaly_detector_score(g_engine.anomaly_detector);
}

NETGUARD_API NetGuardError netguard_get_baseline(AnomalyBaseline* baseline) {
    if (!baseline || !g_engine.anomaly_detector) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    memcpy(baseline, &g_engine.anomaly_detector->baseline, sizeof(AnomalyBaseline));
    return NETGUARD_OK;
}
