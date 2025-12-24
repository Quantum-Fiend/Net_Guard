/*
 * Net_Guard - Ring Buffer Implementation
 * Lock-free circular buffer for high-throughput packet queuing
 */

#include "netguard_internal.h"

/* Create a new ring buffer with power-of-2 capacity */
RingBuffer* ring_buffer_create(uint32_t capacity) {
    /* Round up to next power of 2 */
    uint32_t n = capacity - 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n++;
    
    RingBuffer* rb = (RingBuffer*)malloc(sizeof(RingBuffer));
    if (!rb) return NULL;
    
    rb->packets = (ParsedPacket*)calloc(n, sizeof(ParsedPacket));
    if (!rb->packets) {
        free(rb);
        return NULL;
    }
    
    rb->capacity = n;
    rb->mask = n - 1;
    rb->head = 0;
    rb->tail = 0;
    
    ng_mutex_init(&rb->mutex);
    ng_cond_init(&rb->not_empty);
    ng_cond_init(&rb->not_full);
    
    return rb;
}

/* Destroy ring buffer */
void ring_buffer_destroy(RingBuffer* rb) {
    if (!rb) return;
    
    ng_mutex_destroy(&rb->mutex);
    
    if (rb->packets) {
        free(rb->packets);
    }
    free(rb);
}

/* Push packet to buffer (producer side) */
bool ring_buffer_push(RingBuffer* rb, const ParsedPacket* packet) {
    if (!rb || !packet) return false;
    
    ng_mutex_lock(&rb->mutex);
    
    /* Check if full */
    uint32_t next_head = (rb->head + 1) & rb->mask;
    if (next_head == rb->tail) {
        ng_mutex_unlock(&rb->mutex);
        return false;  /* Buffer full, drop packet */
    }
    
    /* Copy packet data */
    memcpy(&rb->packets[rb->head], packet, sizeof(ParsedPacket));
    
    /* If packet has raw data, we need to copy it too */
    if (packet->raw_data && packet->raw_length > 0) {
        rb->packets[rb->head].raw_data = (uint8_t*)malloc(packet->raw_length);
        if (rb->packets[rb->head].raw_data) {
            memcpy(rb->packets[rb->head].raw_data, packet->raw_data, packet->raw_length);
        }
    }
    
    /* Advance head */
    rb->head = next_head;
    
    /* Signal consumers */
    ng_cond_signal(&rb->not_empty);
    
    ng_mutex_unlock(&rb->mutex);
    return true;
}

/* Pop packet from buffer (consumer side) */
bool ring_buffer_pop(RingBuffer* rb, ParsedPacket* packet) {
    if (!rb || !packet) return false;
    
    ng_mutex_lock(&rb->mutex);
    
    /* Check if empty */
    if (rb->head == rb->tail) {
        ng_mutex_unlock(&rb->mutex);
        return false;
    }
    
    /* Copy packet data */
    memcpy(packet, &rb->packets[rb->tail], sizeof(ParsedPacket));
    
    /* Clear the slot */
    memset(&rb->packets[rb->tail], 0, sizeof(ParsedPacket));
    
    /* Advance tail */
    rb->tail = (rb->tail + 1) & rb->mask;
    
    /* Signal producers */
    ng_cond_signal(&rb->not_full);
    
    ng_mutex_unlock(&rb->mutex);
    return true;
}

/* Get current size */
uint32_t ring_buffer_size(RingBuffer* rb) {
    if (!rb) return 0;
    uint32_t head = rb->head;
    uint32_t tail = rb->tail;
    return (head - tail) & rb->mask;
}

/* Check if empty */
bool ring_buffer_is_empty(RingBuffer* rb) {
    if (!rb) return true;
    return rb->head == rb->tail;
}

/* Check if full */
bool ring_buffer_is_full(RingBuffer* rb) {
    if (!rb) return true;
    return ((rb->head + 1) & rb->mask) == rb->tail;
}
