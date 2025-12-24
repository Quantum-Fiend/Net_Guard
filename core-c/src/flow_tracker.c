/*
 * Net_Guard - Flow Tracker Implementation
 * Track TCP/UDP connections with state management
 */

#include "netguard_internal.h"

/* Create flow table */
FlowTable* flow_table_create(void) {
    FlowTable* table = (FlowTable*)malloc(sizeof(FlowTable));
    if (!table) return NULL;
    
    table->buckets = (FlowEntry**)calloc(FLOW_TABLE_SIZE, sizeof(FlowEntry*));
    if (!table->buckets) {
        free(table);
        return NULL;
    }
    
    table->size = FLOW_TABLE_SIZE;
    table->count = 0;
    ng_mutex_init(&table->mutex);
    
    /* Create memory pool for flow entries */
    table->entry_pool = memory_pool_create(sizeof(FlowEntry), MAX_FLOWS);
    if (!table->entry_pool) {
        free(table->buckets);
        free(table);
        return NULL;
    }
    
    return table;
}

/* Destroy flow table */
void flow_table_destroy(FlowTable* table) {
    if (!table) return;
    
    ng_mutex_lock(&table->mutex);
    
    /* Free all entries */
    for (uint32_t i = 0; i < table->size; i++) {
        FlowEntry* entry = table->buckets[i];
        while (entry) {
            FlowEntry* next = entry->next;
            memory_pool_free(table->entry_pool, entry);
            entry = next;
        }
        table->buckets[i] = NULL;
    }
    
    ng_mutex_unlock(&table->mutex);
    ng_mutex_destroy(&table->mutex);
    
    if (table->entry_pool) {
        memory_pool_destroy(table->entry_pool);
    }
    
    free(table->buckets);
    free(table);
}

/* Lookup flow by hash */
FlowRecord* flow_table_lookup(FlowTable* table, uint64_t hash) {
    if (!table) return NULL;
    
    uint32_t bucket = hash % table->size;
    
    ng_mutex_lock(&table->mutex);
    
    FlowEntry* entry = table->buckets[bucket];
    while (entry) {
        if (entry->flow.flow_hash == hash) {
            ng_mutex_unlock(&table->mutex);
            return &entry->flow;
        }
        entry = entry->next;
    }
    
    ng_mutex_unlock(&table->mutex);
    return NULL;
}

/* Insert or update flow */
FlowRecord* flow_table_insert(FlowTable* table, const FlowRecord* flow) {
    if (!table || !flow) return NULL;
    
    uint32_t bucket = flow->flow_hash % table->size;
    
    ng_mutex_lock(&table->mutex);
    
    /* Check if flow already exists */
    FlowEntry* entry = table->buckets[bucket];
    while (entry) {
        if (entry->flow.flow_hash == flow->flow_hash) {
            /* Update existing flow */
            entry->flow.last_seen = flow->last_seen;
            entry->flow.packets_sent += flow->packets_sent;
            entry->flow.packets_recv += flow->packets_recv;
            entry->flow.bytes_sent += flow->bytes_sent;
            entry->flow.bytes_recv += flow->bytes_recv;
            entry->flow.tcp_flags_seen |= flow->tcp_flags_seen;
            entry->flow.state = flow->state;
            
            ng_mutex_unlock(&table->mutex);
            return &entry->flow;
        }
        entry = entry->next;
    }
    
    /* Create new entry */
    FlowEntry* new_entry = (FlowEntry*)memory_pool_alloc(table->entry_pool);
    if (!new_entry) {
        ng_mutex_unlock(&table->mutex);
        return NULL;
    }
    
    memcpy(&new_entry->flow, flow, sizeof(FlowRecord));
    new_entry->next = table->buckets[bucket];
    table->buckets[bucket] = new_entry;
    table->count++;
    
    ng_mutex_unlock(&table->mutex);
    return &new_entry->flow;
}

/* Remove flow by hash */
void flow_table_remove(FlowTable* table, uint64_t hash) {
    if (!table) return;
    
    uint32_t bucket = hash % table->size;
    
    ng_mutex_lock(&table->mutex);
    
    FlowEntry* entry = table->buckets[bucket];
    FlowEntry* prev = NULL;
    
    while (entry) {
        if (entry->flow.flow_hash == hash) {
            if (prev) {
                prev->next = entry->next;
            } else {
                table->buckets[bucket] = entry->next;
            }
            memory_pool_free(table->entry_pool, entry);
            table->count--;
            break;
        }
        prev = entry;
        entry = entry->next;
    }
    
    ng_mutex_unlock(&table->mutex);
}

/* Cleanup expired flows */
void flow_table_cleanup(FlowTable* table, uint64_t current_time_us) {
    if (!table) return;
    
    ng_mutex_lock(&table->mutex);
    
    for (uint32_t i = 0; i < table->size; i++) {
        FlowEntry* entry = table->buckets[i];
        FlowEntry* prev = NULL;
        
        while (entry) {
            FlowEntry* next = entry->next;
            
            /* Calculate timeout based on protocol */
            uint64_t timeout_us;
            switch (entry->flow.protocol) {
                case IP_PROTO_TCP:
                    timeout_us = FLOW_TIMEOUT_TCP * 1000000ULL;
                    break;
                case IP_PROTO_UDP:
                    timeout_us = FLOW_TIMEOUT_UDP * 1000000ULL;
                    break;
                default:
                    timeout_us = FLOW_TIMEOUT_ICMP * 1000000ULL;
                    break;
            }
            
            /* Check for timeout */
            if (current_time_us - entry->flow.last_seen > timeout_us) {
                if (prev) {
                    prev->next = next;
                } else {
                    table->buckets[i] = next;
                }
                
                entry->flow.state = FLOW_STATE_TIMEOUT;
                
                /* Notify callback if set */
                if (g_engine.flow_callback) {
                    g_engine.flow_callback(&entry->flow, false, g_engine.flow_callback_data);
                }
                
                memory_pool_free(table->entry_pool, entry);
                table->count--;
            } else {
                prev = entry;
            }
            
            entry = next;
        }
    }
    
    ng_mutex_unlock(&table->mutex);
}

/* Get flow count */
uint32_t flow_table_count(FlowTable* table) {
    if (!table) return 0;
    return table->count;
}

/* Update flow from packet */
FlowRecord* flow_update_from_packet(FlowTable* table, const ParsedPacket* packet) {
    if (!table || !packet || !packet->has_ip || !packet->has_transport) {
        return NULL;
    }
    
    /* Only track TCP and UDP */
    if (packet->transport_proto != PROTO_TCP && packet->transport_proto != PROTO_UDP) {
        return NULL;
    }
    
    uint16_t src_port, dst_port;
    uint8_t tcp_flags = 0;
    
    if (packet->transport_proto == PROTO_TCP) {
        src_port = packet->transport.tcp.src_port;
        dst_port = packet->transport.tcp.dst_port;
        tcp_flags = packet->transport.tcp.flags;
    } else {
        src_port = packet->transport.udp.src_port;
        dst_port = packet->transport.udp.dst_port;
    }
    
    /* Look up existing flow */
    FlowRecord* flow = flow_table_lookup(table, packet->flow_hash);
    
    if (flow) {
        /* Update existing flow */
        flow->last_seen = packet->timestamp_us;
        
        /* Determine direction and update counts */
        if (flow->src_ip == packet->ip.ipv4.src_ip) {
            flow->packets_sent++;
            flow->bytes_sent += packet->wire_length;
        } else {
            flow->packets_recv++;
            flow->bytes_recv += packet->wire_length;
        }
        
        /* Update TCP state */
        if (packet->transport_proto == PROTO_TCP) {
            flow->tcp_flags_seen |= tcp_flags;
            
            if (tcp_flags & TCP_FLAG_SYN) {
                if (!(tcp_flags & TCP_FLAG_ACK)) {
                    flow->syn_seen = true;
                } else {
                    flow->syn_ack_seen = true;
                    flow->state = FLOW_STATE_ESTABLISHED;
                }
            }
            
            if (tcp_flags & TCP_FLAG_FIN) {
                flow->fin_seen = true;
                flow->state = FLOW_STATE_FIN_WAIT;
            }
            
            if (tcp_flags & TCP_FLAG_RST) {
                flow->state = FLOW_STATE_CLOSED;
            }
        }
        
        return flow;
    }
    
    /* Create new flow */
    FlowRecord new_flow = {0};
    new_flow.src_ip = packet->ip.ipv4.src_ip;
    new_flow.dst_ip = packet->ip.ipv4.dst_ip;
    new_flow.src_port = src_port;
    new_flow.dst_port = dst_port;
    new_flow.protocol = packet->ip.ipv4.protocol;
    new_flow.state = FLOW_STATE_NEW;
    new_flow.first_seen = packet->timestamp_us;
    new_flow.last_seen = packet->timestamp_us;
    new_flow.packets_sent = 1;
    new_flow.bytes_sent = packet->wire_length;
    new_flow.flow_hash = packet->flow_hash;
    
    if (packet->transport_proto == PROTO_TCP) {
        new_flow.tcp_flags_seen = tcp_flags;
        if (tcp_flags & TCP_FLAG_SYN) {
            new_flow.syn_seen = true;
        }
    }
    
    flow = flow_table_insert(table, &new_flow);
    
    /* Notify callback for new flow */
    if (flow && g_engine.flow_callback) {
        g_engine.flow_callback(flow, true, g_engine.flow_callback_data);
    }
    
    return flow;
}

/* Get all active flows (up to max_count) */
NETGUARD_API NetGuardError netguard_get_flows(FlowRecord* flows, uint32_t* count, uint32_t max_count) {
    if (!flows || !count || !g_engine.flow_table) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    FlowTable* table = g_engine.flow_table;
    *count = 0;
    
    ng_mutex_lock(&table->mutex);
    
    for (uint32_t i = 0; i < table->size && *count < max_count; i++) {
        FlowEntry* entry = table->buckets[i];
        while (entry && *count < max_count) {
            memcpy(&flows[*count], &entry->flow, sizeof(FlowRecord));
            (*count)++;
            entry = entry->next;
        }
    }
    
    ng_mutex_unlock(&table->mutex);
    
    return NETGUARD_OK;
}

/* Get single flow by hash */
NETGUARD_API NetGuardError netguard_get_flow(uint64_t flow_hash, FlowRecord* flow) {
    if (!flow || !g_engine.flow_table) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    FlowRecord* found = flow_table_lookup(g_engine.flow_table, flow_hash);
    if (!found) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    
    memcpy(flow, found, sizeof(FlowRecord));
    return NETGUARD_OK;
}

/* Manual flow cleanup */
NETGUARD_API void netguard_cleanup_flows(void) {
    if (g_engine.flow_table) {
        flow_table_cleanup(g_engine.flow_table, current_time_us());
    }
}

/* IP protocol constant for flow tracker reference */
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
