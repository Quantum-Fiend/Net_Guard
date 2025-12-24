/*
 * Net_Guard - Detection Engine Implementation
 * Port scan detection, signature matching, anomaly detection
 */

#include "netguard_internal.h"

/* =============================================================================
 * Port Scan Detection
 * ============================================================================= */

/* Create port scan table */
PortScanTable* port_scan_table_create(void) {
    PortScanTable* table = (PortScanTable*)malloc(sizeof(PortScanTable));
    if (!table) return NULL;
    
    table->buckets = (PortScanEntry**)calloc(PORT_SCAN_TABLE_SIZE, sizeof(PortScanEntry*));
    if (!table->buckets) {
        free(table);
        return NULL;
    }
    
    table->size = PORT_SCAN_TABLE_SIZE;
    ng_mutex_init(&table->mutex);
    table->threshold_ports = PORT_SCAN_THRESHOLD;
    table->window_seconds = PORT_SCAN_WINDOW_SEC;
    
    return table;
}

/* Destroy port scan table */
void port_scan_table_destroy(PortScanTable* table) {
    if (!table) return;
    
    ng_mutex_lock(&table->mutex);
    
    for (uint32_t i = 0; i < table->size; i++) {
        PortScanEntry* entry = table->buckets[i];
        while (entry) {
            PortScanEntry* next = entry->next;
            if (entry->tracker.ports) {
                free(entry->tracker.ports);
            }
            free(entry);
            entry = next;
        }
    }
    
    ng_mutex_unlock(&table->mutex);
    ng_mutex_destroy(&table->mutex);
    
    free(table->buckets);
    free(table);
}

/* Determine scan type from TCP flags */
static AttackType determine_scan_type(uint8_t flags) {
    if (flags == TCP_FLAG_SYN) {
        return ATTACK_PORT_SCAN_SYN;
    } else if (flags == TCP_FLAG_FIN) {
        return ATTACK_PORT_SCAN_FIN;
    } else if (flags == 0) {
        return ATTACK_PORT_SCAN_NULL;
    } else if ((flags & (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) == 
               (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) {
        return ATTACK_PORT_SCAN_XMAS;
    }
    return ATTACK_NONE;
}

/* Check for port scan and return true if detected */
bool port_scan_check(PortScanTable* table, uint32_t src_ip, uint16_t dst_port, 
                     uint8_t tcp_flags, AttackType* scan_type) {
    if (!table || !scan_type) return false;
    
    *scan_type = ATTACK_NONE;
    
    /* Only check certain TCP flag combinations */
    AttackType detected_type = determine_scan_type(tcp_flags);
    if (detected_type == ATTACK_NONE && tcp_flags != 0) {
        return false;  /* Normal traffic */
    }
    
    uint32_t bucket = src_ip % table->size;
    uint64_t current_time = current_time_us();
    uint64_t window_us = table->window_seconds * 1000000ULL;
    
    ng_mutex_lock(&table->mutex);
    
    /* Find or create entry for this source IP */
    PortScanEntry* entry = table->buckets[bucket];
    PortScanEntry* target = NULL;
    
    while (entry) {
        if (entry->tracker.src_ip == src_ip) {
            target = entry;
            break;
        }
        entry = entry->next;
    }
    
    if (!target) {
        /* Create new entry */
        target = (PortScanEntry*)calloc(1, sizeof(PortScanEntry));
        if (!target) {
            ng_mutex_unlock(&table->mutex);
            return false;
        }
        
        target->tracker.src_ip = src_ip;
        target->tracker.port_capacity = 64;
        target->tracker.ports = (uint16_t*)malloc(64 * sizeof(uint16_t));
        if (!target->tracker.ports) {
            free(target);
            ng_mutex_unlock(&table->mutex);
            return false;
        }
        target->tracker.port_count = 0;
        target->tracker.first_seen = current_time;
        target->tracker.scan_type = detected_type;
        
        target->next = table->buckets[bucket];
        table->buckets[bucket] = target;
    }
    
    /* Check if window expired, reset if so */
    if (current_time - target->tracker.first_seen > window_us) {
        target->tracker.port_count = 0;
        target->tracker.first_seen = current_time;
        target->tracker.scan_type = detected_type;
    }
    
    target->tracker.last_seen = current_time;
    
    /* Check if this port is already tracked */
    bool port_exists = false;
    for (uint32_t i = 0; i < target->tracker.port_count; i++) {
        if (target->tracker.ports[i] == dst_port) {
            port_exists = true;
            break;
        }
    }
    
    /* Add new port */
    if (!port_exists) {
        /* Expand array if needed */
        if (target->tracker.port_count >= target->tracker.port_capacity) {
            uint32_t new_capacity = target->tracker.port_capacity * 2;
            uint16_t* new_ports = (uint16_t*)realloc(target->tracker.ports, 
                                                      new_capacity * sizeof(uint16_t));
            if (new_ports) {
                target->tracker.ports = new_ports;
                target->tracker.port_capacity = new_capacity;
            }
        }
        
        if (target->tracker.port_count < target->tracker.port_capacity) {
            target->tracker.ports[target->tracker.port_count++] = dst_port;
        }
    }
    
    /* Check threshold */
    bool is_scan = target->tracker.port_count >= table->threshold_ports;
    if (is_scan) {
        *scan_type = (target->tracker.scan_type != ATTACK_NONE) ? 
                     target->tracker.scan_type : ATTACK_PORT_SCAN_SYN;
    }
    
    ng_mutex_unlock(&table->mutex);
    
    return is_scan;
}

/* Cleanup old port scan entries */
void port_scan_cleanup(PortScanTable* table, uint64_t current_time) {
    if (!table) return;
    
    uint64_t window_us = table->window_seconds * 2 * 1000000ULL;  /* 2x window for cleanup */
    
    ng_mutex_lock(&table->mutex);
    
    for (uint32_t i = 0; i < table->size; i++) {
        PortScanEntry* entry = table->buckets[i];
        PortScanEntry* prev = NULL;
        
        while (entry) {
            PortScanEntry* next = entry->next;
            
            if (current_time - entry->tracker.last_seen > window_us) {
                if (prev) {
                    prev->next = next;
                } else {
                    table->buckets[i] = next;
                }
                
                if (entry->tracker.ports) {
                    free(entry->tracker.ports);
                }
                free(entry);
            } else {
                prev = entry;
            }
            
            entry = next;
        }
    }
    
    ng_mutex_unlock(&table->mutex);
}

/* =============================================================================
 * Signature Engine
 * ============================================================================= */

/* Create signature engine */
SignatureEngine* signature_engine_create(void) {
    SignatureEngine* engine = (SignatureEngine*)calloc(1, sizeof(SignatureEngine));
    if (!engine) return NULL;
    
    ng_mutex_init(&engine->mutex);
    engine->count = 0;
    
    return engine;
}

/* Destroy signature engine */
void signature_engine_destroy(SignatureEngine* engine) {
    if (!engine) return;
    
    ng_mutex_lock(&engine->mutex);
    
    /* Free Boyer-Moore tables */
    for (uint32_t i = 0; i < engine->count; i++) {
        if (engine->bad_char_tables[i]) {
            free(engine->bad_char_tables[i]);
        }
        if (engine->good_suffix_tables[i]) {
            free(engine->good_suffix_tables[i]);
        }
    }
    
    ng_mutex_unlock(&engine->mutex);
    ng_mutex_destroy(&engine->mutex);
    
    free(engine);
}

/* Precompute Boyer-Moore bad character table */
static void compute_bad_char_table(const char* pattern, uint32_t len, int* table) {
    for (int i = 0; i < 256; i++) {
        table[i] = -1;
    }
    for (uint32_t i = 0; i < len; i++) {
        table[(unsigned char)pattern[i]] = i;
    }
}

/* Add signature rule */
bool signature_engine_add(SignatureEngine* engine, const DetectionRule* rule) {
    if (!engine || !rule || engine->count >= MAX_SIGNATURES) {
        return false;
    }
    
    ng_mutex_lock(&engine->mutex);
    
    uint32_t idx = engine->count;
    memcpy(&engine->rules[idx], rule, sizeof(DetectionRule));
    engine->rules[idx].pattern_length = (uint32_t)strlen(rule->pattern);
    
    /* Precompute Boyer-Moore table */
    engine->bad_char_tables[idx] = (int*)malloc(256 * sizeof(int));
    if (engine->bad_char_tables[idx]) {
        compute_bad_char_table(rule->pattern, engine->rules[idx].pattern_length, 
                               engine->bad_char_tables[idx]);
    }
    
    engine->count++;
    
    ng_mutex_unlock(&engine->mutex);
    return true;
}

/* Remove signature rule by name */
bool signature_engine_remove(SignatureEngine* engine, const char* name) {
    if (!engine || !name) return false;
    
    ng_mutex_lock(&engine->mutex);
    
    for (uint32_t i = 0; i < engine->count; i++) {
        if (strcmp(engine->rules[i].name, name) == 0) {
            /* Free tables */
            if (engine->bad_char_tables[i]) {
                free(engine->bad_char_tables[i]);
            }
            if (engine->good_suffix_tables[i]) {
                free(engine->good_suffix_tables[i]);
            }
            
            /* Shift remaining rules */
            for (uint32_t j = i; j < engine->count - 1; j++) {
                memcpy(&engine->rules[j], &engine->rules[j + 1], sizeof(DetectionRule));
                engine->bad_char_tables[j] = engine->bad_char_tables[j + 1];
                engine->good_suffix_tables[j] = engine->good_suffix_tables[j + 1];
            }
            engine->count--;
            
            ng_mutex_unlock(&engine->mutex);
            return true;
        }
    }
    
    ng_mutex_unlock(&engine->mutex);
    return false;
}

/* Clear all rules */
void signature_engine_clear(SignatureEngine* engine) {
    if (!engine) return;
    
    ng_mutex_lock(&engine->mutex);
    
    for (uint32_t i = 0; i < engine->count; i++) {
        if (engine->bad_char_tables[i]) {
            free(engine->bad_char_tables[i]);
            engine->bad_char_tables[i] = NULL;
        }
        if (engine->good_suffix_tables[i]) {
            free(engine->good_suffix_tables[i]);
            engine->good_suffix_tables[i] = NULL;
        }
    }
    engine->count = 0;
    
    ng_mutex_unlock(&engine->mutex);
}

/* Boyer-Moore search */
static bool boyer_moore_search(const uint8_t* text, uint32_t text_len,
                                const char* pattern, uint32_t pattern_len,
                                const int* bad_char_table) {
    if (pattern_len == 0 || pattern_len > text_len) {
        return false;
    }
    
    int32_t shift = 0;
    while (shift <= (int32_t)(text_len - pattern_len)) {
        int32_t j = pattern_len - 1;
        
        /* Compare from right to left */
        while (j >= 0 && pattern[j] == (char)text[shift + j]) {
            j--;
        }
        
        if (j < 0) {
            return true;  /* Match found */
        }
        
        /* Shift using bad character rule */
        int32_t bc_shift = j - bad_char_table[text[shift + j]];
        shift += (bc_shift > 1) ? bc_shift : 1;
    }
    
    return false;
}

/* Case-insensitive search */
static bool case_insensitive_search(const uint8_t* text, uint32_t text_len,
                                     const char* pattern, uint32_t pattern_len) {
    if (pattern_len == 0 || pattern_len > text_len) {
        return false;
    }
    
    for (uint32_t i = 0; i <= text_len - pattern_len; i++) {
        bool match = true;
        for (uint32_t j = 0; j < pattern_len; j++) {
            char t = (char)text[i + j];
            char p = pattern[j];
            
            /* Convert to lowercase */
            if (t >= 'A' && t <= 'Z') t += 32;
            if (p >= 'A' && p <= 'Z') p += 32;
            
            if (t != p) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    
    return false;
}

/* Match packet against all signatures */
bool signature_engine_match(SignatureEngine* engine, const ParsedPacket* packet, 
                            DetectionRule* matched_rule) {
    if (!engine || !packet || !packet->payload || packet->payload_length == 0) {
        return false;
    }
    
    ng_mutex_lock(&engine->mutex);
    
    for (uint32_t i = 0; i < engine->count; i++) {
        DetectionRule* rule = &engine->rules[i];
        
        if (!rule->enabled) continue;
        
        /* Check protocol match */
        if (rule->protocol != PROTO_UNKNOWN && rule->protocol != packet->transport_proto) {
            continue;
        }
        
        /* Check port match */
        if (!rule->any_port) {
            uint16_t dst_port = 0;
            if (packet->transport_proto == PROTO_TCP) {
                dst_port = packet->transport.tcp.dst_port;
            } else if (packet->transport_proto == PROTO_UDP) {
                dst_port = packet->transport.udp.dst_port;
            }
            
            if (rule->port != dst_port) {
                continue;
            }
        }
        
        /* Pattern matching */
        bool match = false;
        if (engine->bad_char_tables[i]) {
            match = boyer_moore_search(packet->payload, packet->payload_length,
                                       rule->pattern, rule->pattern_length,
                                       engine->bad_char_tables[i]);
        } else {
            match = case_insensitive_search(packet->payload, packet->payload_length,
                                             rule->pattern, rule->pattern_length);
        }
        
        if (match) {
            if (matched_rule) {
                memcpy(matched_rule, rule, sizeof(DetectionRule));
            }
            ng_mutex_unlock(&engine->mutex);
            return true;
        }
    }
    
    ng_mutex_unlock(&engine->mutex);
    return false;
}

/* =============================================================================
 * Anomaly Detection
 * ============================================================================= */

#define ANOMALY_SAMPLE_WINDOW 60  /* 60 samples for rolling stats */

/* Create anomaly detector */
AnomalyDetector* anomaly_detector_create(void) {
    AnomalyDetector* detector = (AnomalyDetector*)calloc(1, sizeof(AnomalyDetector));
    if (!detector) return NULL;
    
    detector->sample_capacity = ANOMALY_SAMPLE_WINDOW;
    detector->pps_samples = (double*)calloc(ANOMALY_SAMPLE_WINDOW, sizeof(double));
    detector->bps_samples = (double*)calloc(ANOMALY_SAMPLE_WINDOW, sizeof(double));
    
    if (!detector->pps_samples || !detector->bps_samples) {
        if (detector->pps_samples) free(detector->pps_samples);
        if (detector->bps_samples) free(detector->bps_samples);
        free(detector);
        return NULL;
    }
    
    ng_mutex_init(&detector->mutex);
    
    return detector;
}

/* Destroy anomaly detector */
void anomaly_detector_destroy(AnomalyDetector* detector) {
    if (!detector) return;
    
    ng_mutex_destroy(&detector->mutex);
    
    if (detector->pps_samples) free(detector->pps_samples);
    if (detector->bps_samples) free(detector->bps_samples);
    free(detector);
}

/* Update anomaly detector with new sample */
void anomaly_detector_update(AnomalyDetector* detector, uint64_t packets, 
                              uint64_t bytes, uint64_t time_us) {
    if (!detector) return;
    
    ng_mutex_lock(&detector->mutex);
    
    /* Calculate rates */
    if (detector->last_update > 0) {
        double elapsed_sec = (time_us - detector->last_update) / 1000000.0;
        if (elapsed_sec > 0) {
            detector->current_pps = packets / elapsed_sec;
            detector->current_bps = bytes / elapsed_sec;
            
            /* Store samples */
            detector->pps_samples[detector->sample_index] = detector->current_pps;
            detector->bps_samples[detector->sample_index] = detector->current_bps;
            detector->sample_index = (detector->sample_index + 1) % detector->sample_capacity;
            if (detector->sample_count < detector->sample_capacity) {
                detector->sample_count++;
            }
            
            /* Update baseline if training */
            if (detector->training) {
                double n = (double)detector->baseline.sample_count + 1;
                double delta_pps = detector->current_pps - detector->baseline.pps_mean;
                detector->baseline.pps_mean += delta_pps / n;
                detector->baseline.pps_stddev += delta_pps * (detector->current_pps - detector->baseline.pps_mean);
                
                double delta_bps = detector->current_bps - detector->baseline.bps_mean;
                detector->baseline.bps_mean += delta_bps / n;
                detector->baseline.bps_stddev += delta_bps * (detector->current_bps - detector->baseline.bps_mean);
                
                detector->baseline.sample_count++;
                
                /* Check if training complete */
                if (time_us - detector->training_start >= detector->training_duration * 1000000ULL) {
                    detector->training = false;
                    detector->baseline.is_trained = true;
                    
                    /* Finalize stddev */
                    if (detector->baseline.sample_count > 1) {
                        detector->baseline.pps_stddev = sqrt(detector->baseline.pps_stddev / 
                                                             (detector->baseline.sample_count - 1));
                        detector->baseline.bps_stddev = sqrt(detector->baseline.bps_stddev / 
                                                             (detector->baseline.sample_count - 1));
                    }
                }
            }
        }
    }
    
    detector->last_update = time_us;
    
    ng_mutex_unlock(&detector->mutex);
}

/* Calculate anomaly Z-score */
double anomaly_detector_score(AnomalyDetector* detector) {
    if (!detector || !detector->baseline.is_trained) {
        return 0.0;
    }
    
    ng_mutex_lock(&detector->mutex);
    
    double z_pps = 0.0;
    double z_bps = 0.0;
    
    if (detector->baseline.pps_stddev > 0) {
        z_pps = (detector->current_pps - detector->baseline.pps_mean) / detector->baseline.pps_stddev;
    }
    
    if (detector->baseline.bps_stddev > 0) {
        z_bps = (detector->current_bps - detector->baseline.bps_mean) / detector->baseline.bps_stddev;
    }
    
    /* Return max absolute Z-score */
    double score = fabs(z_pps) > fabs(z_bps) ? fabs(z_pps) : fabs(z_bps);
    
    ng_mutex_unlock(&detector->mutex);
    
    return score;
}

/* Start baseline training */
void anomaly_detector_train(AnomalyDetector* detector, uint32_t duration_seconds) {
    if (!detector) return;
    
    ng_mutex_lock(&detector->mutex);
    
    /* Reset baseline */
    memset(&detector->baseline, 0, sizeof(AnomalyBaseline));
    detector->training = true;
    detector->training_start = current_time_us();
    detector->training_duration = duration_seconds;
    
    ng_mutex_unlock(&detector->mutex);
}

/* Check if baseline is trained */
bool anomaly_detector_is_ready(AnomalyDetector* detector) {
    if (!detector) return false;
    return detector->baseline.is_trained;
}

/* =============================================================================
 * Entropy Calculation
 * ============================================================================= */

/* Calculate Shannon entropy of data */
double calculate_entropy(const uint8_t* data, uint32_t length) {
    if (!data || length == 0) return 0.0;
    
    uint32_t freq[256] = {0};
    
    /* Count byte frequencies */
    for (uint32_t i = 0; i < length; i++) {
        freq[data[i]]++;
    }
    
    /* Calculate entropy */
    double entropy = 0.0;
    double n = (double)length;
    
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / n;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

/* API wrapper */
NETGUARD_API double netguard_calculate_entropy(const uint8_t* data, uint32_t length) {
    return calculate_entropy(data, length);
}

/* =============================================================================
 * Alert Generation
 * ============================================================================= */

/* Generate and dispatch alert */
void generate_alert(AttackType type, AlertSeverity severity, 
                    const ParsedPacket* packet, const char* description) {
    if (!g_engine.alert_callback) return;
    
    Alert alert = {0};
    alert.timestamp = current_time_us();
    alert.attack_type = type;
    alert.severity = severity;
    
    if (packet && packet->has_ip) {
        alert.src_ip = packet->ip.ipv4.src_ip;
        alert.dst_ip = packet->ip.ipv4.dst_ip;
        alert.protocol = packet->ip.ipv4.protocol;
        
        if (packet->has_transport) {
            if (packet->transport_proto == PROTO_TCP) {
                alert.src_port = packet->transport.tcp.src_port;
                alert.dst_port = packet->transport.tcp.dst_port;
            } else if (packet->transport_proto == PROTO_UDP) {
                alert.src_port = packet->transport.udp.src_port;
                alert.dst_port = packet->transport.udp.dst_port;
            }
        }
        
        /* Copy packet snapshot */
        uint32_t snapshot_len = packet->raw_length < 256 ? packet->raw_length : 256;
        memcpy(alert.packet_snapshot, packet->raw_data, snapshot_len);
        alert.snapshot_length = snapshot_len;
    }
    
    if (description) {
        strncpy(alert.description, description, sizeof(alert.description) - 1);
    }
    
    /* Invoke callback */
    g_engine.alert_callback(&alert, g_engine.alert_callback_data);
    
    /* Update stats */
    ng_atomic_inc(&g_engine.stats.alerts_generated);
}
