/*
 * Net_Guard - IPC Bridge
 * DLL export interface for C# P/Invoke interoperability
 */

#include "netguard_internal.h"
#include <stdarg.h>

/* =============================================================================
 * JSON Rule Loading
 * ============================================================================= */

/* Simple JSON parser for rule files */
static char* read_file(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* buffer = (char*)malloc(*size + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    fread(buffer, 1, *size, f);
    buffer[*size] = '\0';
    fclose(f);
    
    return buffer;
}

/* Skip whitespace */
static const char* skip_ws(const char* s) {
    while (*s && (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')) s++;
    return s;
}

/* Parse a JSON string value */
static bool parse_json_string(const char** s, char* out, size_t max_len) {
    const char* p = *s;
    p = skip_ws(p);
    
    if (*p != '"') return false;
    p++;
    
    size_t i = 0;
    while (*p && *p != '"' && i < max_len - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
                case 'n': out[i++] = '\n'; break;
                case 'r': out[i++] = '\r'; break;
                case 't': out[i++] = '\t'; break;
                case '\\': out[i++] = '\\'; break;
                case '"': out[i++] = '"'; break;
                default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    
    if (*p == '"') p++;
    *s = p;
    
    return true;
}

/* Parse a JSON integer */
static bool parse_json_int(const char** s, int* out) {
    const char* p = skip_ws(*s);
    char* end;
    long val = strtol(p, &end, 10);
    if (end == p) return false;
    *out = (int)val;
    *s = end;
    return true;
}

/* Find a JSON key */
static const char* find_json_key(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    const char* p = strstr(json, search);
    if (!p) return NULL;
    
    p += strlen(search);
    p = skip_ws(p);
    if (*p != ':') return NULL;
    p++;
    p = skip_ws(p);
    
    return p;
}

/* Parse a single rule from JSON object */
static bool parse_rule_object(const char* json, DetectionRule* rule) {
    memset(rule, 0, sizeof(DetectionRule));
    rule->enabled = true;
    rule->any_port = true;
    
    /* Parse name */
    const char* p = find_json_key(json, "name");
    if (p) parse_json_string(&p, rule->name, MAX_RULE_NAME);
    
    /* Parse pattern */
    p = find_json_key(json, "pattern");
    if (p) parse_json_string(&p, rule->pattern, MAX_PATTERN_SIZE);
    
    /* Parse protocol */
    p = find_json_key(json, "protocol");
    if (p) {
        char proto[16];
        if (parse_json_string(&p, proto, sizeof(proto))) {
            if (strcmp(proto, "TCP") == 0) rule->protocol = PROTO_TCP;
            else if (strcmp(proto, "UDP") == 0) rule->protocol = PROTO_UDP;
            else if (strcmp(proto, "ICMP") == 0) rule->protocol = PROTO_ICMP;
        }
    }
    
    /* Parse port */
    p = find_json_key(json, "port");
    if (p) {
        int port;
        if (parse_json_int(&p, &port)) {
            rule->port = (uint16_t)port;
            rule->any_port = false;
        }
    }
    
    /* Parse severity */
    p = find_json_key(json, "severity");
    if (p) {
        char sev[16];
        if (parse_json_string(&p, sev, sizeof(sev))) {
            if (strcmp(sev, "CRITICAL") == 0) rule->severity = SEVERITY_CRITICAL;
            else if (strcmp(sev, "HIGH") == 0) rule->severity = SEVERITY_HIGH;
            else if (strcmp(sev, "MEDIUM") == 0) rule->severity = SEVERITY_MEDIUM;
            else if (strcmp(sev, "LOW") == 0) rule->severity = SEVERITY_LOW;
            else rule->severity = SEVERITY_INFO;
        }
    }
    
    /* Parse attack_type */
    p = find_json_key(json, "attack_type");
    if (p) {
        char type[32];
        if (parse_json_string(&p, type, sizeof(type))) {
            if (strstr(type, "SIGNATURE")) rule->attack_type = ATTACK_SIGNATURE_MATCH;
            else if (strstr(type, "PORT_SCAN")) rule->attack_type = ATTACK_PORT_SCAN_SYN;
        }
    }
    
    rule->attack_type = ATTACK_SIGNATURE_MATCH;
    
    return strlen(rule->name) > 0 && strlen(rule->pattern) > 0;
}

/* Load rules from JSON file */
NETGUARD_API NetGuardError netguard_load_rules_json(const char* file_path) {
    if (!file_path || !g_engine.signature_engine) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    size_t size;
    char* json = read_file(file_path, &size);
    if (!json) {
        set_error("Failed to read rules file: %s", file_path);
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    /* Find rules array */
    const char* rules_start = find_json_key(json, "rules");
    if (!rules_start) {
        /* Try parsing as array directly */
        rules_start = strchr(json, '[');
    }
    
    if (!rules_start || *rules_start != '[') {
        free(json);
        set_error("Invalid rules format: expected 'rules' array");
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    rules_start++;
    uint32_t rules_loaded = 0;
    
    /* Parse each rule object */
    while (*rules_start) {
        rules_start = skip_ws(rules_start);
        
        if (*rules_start == ']') break;
        if (*rules_start == ',') {
            rules_start++;
            continue;
        }
        
        if (*rules_start == '{') {
            /* Find matching closing brace */
            int depth = 1;
            const char* end = rules_start + 1;
            while (*end && depth > 0) {
                if (*end == '{') depth++;
                else if (*end == '}') depth--;
                end++;
            }
            
            /* Copy object for parsing */
            size_t obj_len = end - rules_start;
            char* obj = (char*)malloc(obj_len + 1);
            if (obj) {
                memcpy(obj, rules_start, obj_len);
                obj[obj_len] = '\0';
                
                DetectionRule rule;
                if (parse_rule_object(obj, &rule)) {
                    if (signature_engine_add(g_engine.signature_engine, &rule)) {
                        rules_loaded++;
                    }
                }
                
                free(obj);
            }
            
            rules_start = end;
        } else {
            rules_start++;
        }
    }
    
    free(json);
    
    if (rules_loaded == 0) {
        set_error("No valid rules found in file");
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    return NETGUARD_OK;
}

/* =============================================================================
 * Exported Data Structures for C# Marshaling
 * ============================================================================= */

/* Simplified structures for P/Invoke */
#pragma pack(push, 1)

typedef struct {
    uint64_t timestamp;
    int32_t attack_type;
    int32_t severity;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    char description[256];
    char rule_name[128];
    double confidence;
} MarshaledAlert;

typedef struct {
    uint64_t packets_captured;
    uint64_t packets_dropped;
    uint64_t packets_processed;
    uint64_t bytes_captured;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;
    uint64_t alerts_generated;
    uint64_t port_scans_detected;
    uint64_t signatures_matched;
    uint64_t anomalies_detected;
    uint32_t active_flows;
    uint64_t total_flows;
    double packets_per_second;
    double bytes_per_second;
    uint64_t uptime_seconds;
} MarshaledStats;

typedef struct {
    char name[256];
    char description[512];
    uint32_t ip_address;
    uint32_t netmask;
    uint8_t mac_address[6];
    int32_t is_loopback;
    int32_t is_up;
} MarshaledDevice;

#pragma pack(pop)

/* Alert buffer for managed code */
#define MAX_ALERT_BUFFER 256
static MarshaledAlert g_alert_buffer[MAX_ALERT_BUFFER];
static volatile uint32_t g_alert_write_idx = 0;
static volatile uint32_t g_alert_read_idx = 0;
static ng_mutex_t g_alert_mutex;
static bool g_alert_buffer_init = false;

/* Initialize alert buffer */
static void init_alert_buffer(void) {
    if (!g_alert_buffer_init) {
        ng_mutex_init(&g_alert_mutex);
        g_alert_buffer_init = true;
    }
}

/* Internal alert callback that stores alerts in buffer */
static void internal_alert_callback(const Alert* alert, void* user_data) {
    (void)user_data;
    
    if (!g_alert_buffer_init) init_alert_buffer();
    
    ng_mutex_lock(&g_alert_mutex);
    
    uint32_t next_write = (g_alert_write_idx + 1) % MAX_ALERT_BUFFER;
    if (next_write != g_alert_read_idx) {
        MarshaledAlert* ma = &g_alert_buffer[g_alert_write_idx];
        
        ma->timestamp = alert->timestamp;
        ma->attack_type = (int32_t)alert->attack_type;
        ma->severity = (int32_t)alert->severity;
        ma->src_ip = alert->src_ip;
        ma->dst_ip = alert->dst_ip;
        ma->src_port = alert->src_port;
        ma->dst_port = alert->dst_port;
        ma->protocol = alert->protocol;
        strncpy(ma->description, alert->description, sizeof(ma->description) - 1);
        strncpy(ma->rule_name, alert->rule_name, sizeof(ma->rule_name) - 1);
        ma->confidence = alert->confidence;
        
        g_alert_write_idx = next_write;
    }
    
    ng_mutex_unlock(&g_alert_mutex);
}

/* =============================================================================
 * P/Invoke Bridge Functions
 * ============================================================================= */

/* Get pending alert count */
NETGUARD_API int32_t __stdcall NetGuard_GetPendingAlertCount(void) {
    if (!g_alert_buffer_init) return 0;
    
    ng_mutex_lock(&g_alert_mutex);
    int32_t count = (g_alert_write_idx - g_alert_read_idx + MAX_ALERT_BUFFER) % MAX_ALERT_BUFFER;
    ng_mutex_unlock(&g_alert_mutex);
    
    return count;
}

/* Get next alert */
NETGUARD_API int32_t __stdcall NetGuard_GetNextAlert(MarshaledAlert* alert) {
    if (!alert || !g_alert_buffer_init) return 0;
    
    ng_mutex_lock(&g_alert_mutex);
    
    if (g_alert_read_idx == g_alert_write_idx) {
        ng_mutex_unlock(&g_alert_mutex);
        return 0;
    }
    
    memcpy(alert, &g_alert_buffer[g_alert_read_idx], sizeof(MarshaledAlert));
    g_alert_read_idx = (g_alert_read_idx + 1) % MAX_ALERT_BUFFER;
    
    ng_mutex_unlock(&g_alert_mutex);
    
    return 1;
}

/* Get current statistics */
NETGUARD_API int32_t __stdcall NetGuard_GetStatistics(MarshaledStats* stats) {
    if (!stats) return -1;
    
    CaptureStats cs;
    if (netguard_get_stats(&cs) != NETGUARD_OK) {
        return -1;
    }
    
    stats->packets_captured = cs.packets_captured;
    stats->packets_dropped = cs.packets_dropped;
    stats->packets_processed = cs.packets_processed;
    stats->bytes_captured = cs.bytes_captured;
    stats->tcp_packets = cs.tcp_packets;
    stats->udp_packets = cs.udp_packets;
    stats->icmp_packets = cs.icmp_packets;
    stats->other_packets = cs.other_packets;
    stats->alerts_generated = cs.alerts_generated;
    stats->port_scans_detected = cs.port_scans_detected;
    stats->signatures_matched = cs.signatures_matched;
    stats->anomalies_detected = cs.anomalies_detected;
    stats->active_flows = cs.active_flows;
    stats->total_flows = cs.total_flows;
    stats->packets_per_second = cs.packets_per_second;
    stats->bytes_per_second = cs.bytes_per_second;
    stats->uptime_seconds = cs.uptime_seconds;
    
    return 0;
}

/* Get available devices */
NETGUARD_API int32_t __stdcall NetGuard_GetDevices(MarshaledDevice* devices, int32_t max_count) {
    if (!devices || max_count <= 0) return -1;
    
    NetDevice* temp = (NetDevice*)malloc(max_count * sizeof(NetDevice));
    if (!temp) return -1;
    
    uint32_t count = (uint32_t)max_count;
    if (netguard_get_devices(temp, &count) != NETGUARD_OK) {
        free(temp);
        return -1;
    }
    
    for (uint32_t i = 0; i < count; i++) {
        strncpy(devices[i].name, temp[i].name, sizeof(devices[i].name) - 1);
        strncpy(devices[i].description, temp[i].description, sizeof(devices[i].description) - 1);
        devices[i].ip_address = temp[i].ip_address;
        devices[i].netmask = temp[i].netmask;
        memcpy(devices[i].mac_address, temp[i].mac_address, 6);
        devices[i].is_loopback = temp[i].is_loopback ? 1 : 0;
        devices[i].is_up = temp[i].is_up ? 1 : 0;
    }
    
    free(temp);
    return (int32_t)count;
}

/* Initialize engine */
NETGUARD_API int32_t __stdcall NetGuard_Initialize(void) {
    init_alert_buffer();
    netguard_set_alert_callback(internal_alert_callback, NULL);
    return (int32_t)netguard_init();
}

/* Shutdown engine */
NETGUARD_API void __stdcall NetGuard_Shutdown(void) {
    netguard_shutdown();
}

/* Start capture */
NETGUARD_API int32_t __stdcall NetGuard_StartCapture(const char* device_name, const char* bpf_filter) {
    return (int32_t)netguard_start_capture(device_name, bpf_filter);
}

/* Stop capture */
NETGUARD_API int32_t __stdcall NetGuard_StopCapture(void) {
    return (int32_t)netguard_stop_capture();
}

/* Check if running */
NETGUARD_API int32_t __stdcall NetGuard_IsRunning(void) {
    return netguard_is_running() ? 1 : 0;
}

/* Set promiscuous mode */
NETGUARD_API void __stdcall NetGuard_SetPromiscuous(int32_t enabled) {
    netguard_set_promiscuous(enabled != 0);
}

/* Enable/disable detection */
NETGUARD_API void __stdcall NetGuard_EnablePortScanDetection(int32_t enabled) {
    netguard_enable_port_scan_detection(enabled != 0);
}

NETGUARD_API void __stdcall NetGuard_EnableSignatureDetection(int32_t enabled) {
    netguard_enable_signature_detection(enabled != 0);
}

NETGUARD_API void __stdcall NetGuard_EnableAnomalyDetection(int32_t enabled) {
    netguard_enable_anomaly_detection(enabled != 0);
}

NETGUARD_API void __stdcall NetGuard_EnableTLSFingerprinting(int32_t enabled) {
    netguard_enable_tls_fingerprinting(enabled != 0);
}

/* Load rules from file */
NETGUARD_API int32_t __stdcall NetGuard_LoadRules(const char* file_path) {
    return (int32_t)netguard_load_rules_json(file_path);
}

/* Get rule count */
NETGUARD_API int32_t __stdcall NetGuard_GetRuleCount(void) {
    return (int32_t)netguard_get_rule_count();
}

/* Train anomaly baseline */
NETGUARD_API int32_t __stdcall NetGuard_TrainBaseline(int32_t duration_seconds) {
    return (int32_t)netguard_train_baseline((uint32_t)duration_seconds);
}

/* Check baseline status */
NETGUARD_API int32_t __stdcall NetGuard_IsBaselineReady(void) {
    return netguard_baseline_ready() ? 1 : 0;
}

/* Get anomaly score */
NETGUARD_API double __stdcall NetGuard_GetAnomalyScore(void) {
    return netguard_get_anomaly_score();
}

/* Get version */
NETGUARD_API const char* __stdcall NetGuard_GetVersion(void) {
    return netguard_version();
}

/* Get last error */
NETGUARD_API const char* __stdcall NetGuard_GetLastError(void) {
    return netguard_get_error();
}

/* PCAP Exports */
NETGUARD_API int32_t __stdcall NetGuard_StartPcap(const char* filepath) {
    return (int32_t)netguard_start_pcap(filepath);
}

NETGUARD_API int32_t __stdcall NetGuard_StopPcap(void) {
    return (int32_t)netguard_stop_pcap();
}
