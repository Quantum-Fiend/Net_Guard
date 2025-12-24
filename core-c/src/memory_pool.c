/*
 * Net_Guard - Memory Pool Implementation
 * Fixed-size block allocator for zero-fragmentation memory management
 */

#include "netguard_internal.h"

/* Create a new memory pool */
MemoryPool* memory_pool_create(size_t block_size, size_t block_count) {
    /* Ensure block size can hold at least a pointer for free list */
    if (block_size < sizeof(MemoryBlock)) {
        block_size = sizeof(MemoryBlock);
    }
    
    /* Align block size to 8 bytes */
    block_size = (block_size + 7) & ~7;
    
    MemoryPool* pool = (MemoryPool*)malloc(sizeof(MemoryPool));
    if (!pool) return NULL;
    
    /* Allocate contiguous memory for all blocks */
    pool->memory = (uint8_t*)malloc(block_size * block_count);
    if (!pool->memory) {
        free(pool);
        return NULL;
    }
    
    pool->block_size = block_size;
    pool->block_count = block_count;
    pool->used_blocks = 0;
    ng_mutex_init(&pool->mutex);
    
    /* Initialize free list */
    pool->free_list = NULL;
    for (size_t i = 0; i < block_count; i++) {
        MemoryBlock* block = (MemoryBlock*)(pool->memory + (i * block_size));
        block->next = pool->free_list;
        pool->free_list = block;
    }
    
    return pool;
}

/* Destroy memory pool */
void memory_pool_destroy(MemoryPool* pool) {
    if (!pool) return;
    
    ng_mutex_destroy(&pool->mutex);
    
    if (pool->memory) {
        free(pool->memory);
    }
    free(pool);
}

/* Allocate a block from the pool */
void* memory_pool_alloc(MemoryPool* pool) {
    if (!pool) return NULL;
    
    ng_mutex_lock(&pool->mutex);
    
    if (!pool->free_list) {
        ng_mutex_unlock(&pool->mutex);
        return NULL;  /* Pool exhausted */
    }
    
    /* Pop from free list */
    MemoryBlock* block = pool->free_list;
    pool->free_list = block->next;
    pool->used_blocks++;
    
    ng_mutex_unlock(&pool->mutex);
    
    /* Zero the block before returning */
    memset(block, 0, pool->block_size);
    return block;
}

/* Return a block to the pool */
void memory_pool_free(MemoryPool* pool, void* ptr) {
    if (!pool || !ptr) return;
    
    /* Validate pointer is within pool bounds */
    uint8_t* block_ptr = (uint8_t*)ptr;
    if (block_ptr < pool->memory || 
        block_ptr >= pool->memory + (pool->block_size * pool->block_count)) {
        return;  /* Invalid pointer */
    }
    
    ng_mutex_lock(&pool->mutex);
    
    /* Push to free list */
    MemoryBlock* block = (MemoryBlock*)ptr;
    block->next = pool->free_list;
    pool->free_list = block;
    pool->used_blocks--;
    
    ng_mutex_unlock(&pool->mutex);
}

/* Get number of used blocks */
size_t memory_pool_used(MemoryPool* pool) {
    if (!pool) return 0;
    return pool->used_blocks;
}

/* Get free block count */
size_t memory_pool_available(MemoryPool* pool) {
    if (!pool) return 0;
    return pool->block_count - pool->used_blocks;
}

/* Reset pool - return all blocks to free list */
void memory_pool_reset(MemoryPool* pool) {
    if (!pool) return;
    
    ng_mutex_lock(&pool->mutex);
    
    pool->free_list = NULL;
    pool->used_blocks = 0;
    
    for (size_t i = 0; i < pool->block_count; i++) {
        MemoryBlock* block = (MemoryBlock*)(pool->memory + (i * pool->block_size));
        block->next = pool->free_list;
        pool->free_list = block;
    }
    
    ng_mutex_unlock(&pool->mutex);
}
