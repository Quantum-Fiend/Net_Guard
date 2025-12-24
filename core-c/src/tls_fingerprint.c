/*
 * Net_Guard - TLS Fingerprinting Implementation
 * JA3/JA3S hash generation for encrypted traffic analysis
 */

#include "netguard_internal.h"
#include <math.h>

/* TLS record types */
#define TLS_RECORD_HANDSHAKE    22
#define TLS_HANDSHAKE_CLIENT_HELLO  1
#define TLS_HANDSHAKE_SERVER_HELLO  2

/* TLS extension types of interest */
#define TLS_EXT_SNI             0
#define TLS_EXT_SUPPORTED_GROUPS 10
#define TLS_EXT_EC_POINT_FORMATS 11

/* Simple MD5 implementation for JA3 hash */
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} MD5_CTX;

static void md5_init(MD5_CTX* ctx);
static void md5_update(MD5_CTX* ctx, const uint8_t* data, uint32_t len);
static void md5_final(uint8_t digest[16], MD5_CTX* ctx);

/* MD5 constants */
static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t m[16];
    
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)block[j]) | (((uint32_t)block[j+1]) << 8) |
               (((uint32_t)block[j+2]) << 16) | (((uint32_t)block[j+3]) << 24);
    }
    
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5*i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3*i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7*i) % 16;
        }
        
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + ROTATE_LEFT((a + f + md5_k[i] + m[g]), md5_s[i]);
        a = tmp;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void md5_init(MD5_CTX* ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(MD5_CTX* ctx, const uint8_t* data, uint32_t len) {
    uint32_t index = (ctx->count[0] >> 3) & 0x3F;
    
    if ((ctx->count[0] += (len << 3)) < (len << 3)) {
        ctx->count[1]++;
    }
    ctx->count[1] += (len >> 29);
    
    uint32_t part_len = 64 - index;
    uint32_t i = 0;
    
    if (len >= part_len) {
        memcpy(&ctx->buffer[index], data, part_len);
        md5_transform(ctx->state, ctx->buffer);
        
        for (i = part_len; i + 63 < len; i += 64) {
            md5_transform(ctx->state, &data[i]);
        }
        index = 0;
    }
    
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

static void md5_final(uint8_t digest[16], MD5_CTX* ctx) {
    uint8_t bits[8];
    for (int i = 0; i < 4; i++) {
        bits[i] = (ctx->count[0] >> (i * 8)) & 0xFF;
        bits[i + 4] = (ctx->count[1] >> (i * 8)) & 0xFF;
    }
    
    uint32_t index = (ctx->count[0] >> 3) & 0x3F;
    uint32_t pad_len = (index < 56) ? (56 - index) : (120 - index);
    
    uint8_t padding[64] = {0x80};
    md5_update(ctx, padding, pad_len);
    md5_update(ctx, bits, 8);
    
    for (int i = 0; i < 4; i++) {
        digest[i] = (ctx->state[0] >> (i * 8)) & 0xFF;
        digest[i + 4] = (ctx->state[1] >> (i * 8)) & 0xFF;
        digest[i + 8] = (ctx->state[2] >> (i * 8)) & 0xFF;
        digest[i + 12] = (ctx->state[3] >> (i * 8)) & 0xFF;
    }
}

/* =============================================================================
 * TLS Fingerprinter
 * ============================================================================= */

/* Create TLS fingerprinter */
TLSFingerprinter* tls_fingerprinter_create(void) {
    TLSFingerprinter* fp = (TLSFingerprinter*)calloc(1, sizeof(TLSFingerprinter));
    if (!fp) return NULL;
    
    fp->blocked_capacity = 64;
    fp->blocked_hashes = (char**)malloc(64 * sizeof(char*));
    fp->blocked_descriptions = (char**)malloc(64 * sizeof(char*));
    
    if (!fp->blocked_hashes || !fp->blocked_descriptions) {
        if (fp->blocked_hashes) free(fp->blocked_hashes);
        if (fp->blocked_descriptions) free(fp->blocked_descriptions);
        free(fp);
        return NULL;
    }
    
    ng_mutex_init(&fp->mutex);
    
    return fp;
}

/* Destroy TLS fingerprinter */
void tls_fingerprinter_destroy(TLSFingerprinter* fp) {
    if (!fp) return;
    
    ng_mutex_lock(&fp->mutex);
    
    for (uint32_t i = 0; i < fp->blocked_count; i++) {
        if (fp->blocked_hashes[i]) free(fp->blocked_hashes[i]);
        if (fp->blocked_descriptions[i]) free(fp->blocked_descriptions[i]);
    }
    
    ng_mutex_unlock(&fp->mutex);
    ng_mutex_destroy(&fp->mutex);
    
    free(fp->blocked_hashes);
    free(fp->blocked_descriptions);
    free(fp);
}

/* Parse TLS ClientHello and extract fingerprint data */
bool tls_parse_client_hello(const uint8_t* data, uint32_t length, TLSFingerprint* fp) {
    if (!data || !fp || length < 43) {
        return false;
    }
    
    memset(fp, 0, sizeof(TLSFingerprint));
    
    uint32_t offset = 0;
    
    /* TLS record header */
    if (data[offset] != TLS_RECORD_HANDSHAKE) {
        return false;
    }
    offset++;
    
    /* TLS version in record */
    fp->tls_version = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    /* Record length */
    uint16_t record_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if (offset + record_len > length) {
        return false;
    }
    
    /* Handshake type */
    if (data[offset] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return false;
    }
    offset++;
    
    /* Handshake length (3 bytes) */
    offset += 3;
    
    /* Client version */
    offset += 2;
    
    /* Client random (32 bytes) */
    offset += 32;
    
    /* Session ID */
    if (offset >= length) return false;
    uint8_t session_id_len = data[offset];
    offset += 1 + session_id_len;
    
    /* Cipher suites */
    if (offset + 2 > length) return false;
    uint16_t cipher_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    uint32_t cipher_count = cipher_len / 2;
    fp->cipher_suites = (uint16_t*)malloc(cipher_count * sizeof(uint16_t));
    if (fp->cipher_suites) {
        fp->cipher_count = cipher_count;
        for (uint32_t i = 0; i < cipher_count && offset + 2 <= length; i++) {
            fp->cipher_suites[i] = (data[offset] << 8) | data[offset + 1];
            offset += 2;
        }
    } else {
        offset += cipher_len;
    }
    
    /* Compression methods */
    if (offset >= length) return true;
    uint8_t comp_len = data[offset];
    offset += 1 + comp_len;
    
    /* Extensions */
    if (offset + 2 > length) return true;
    uint16_t ext_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    /* Count extensions first */
    uint32_t ext_count = 0;
    uint32_t temp_offset = offset;
    while (temp_offset + 4 <= length && temp_offset < offset + ext_len) {
        uint16_t ext_data_len = (data[temp_offset + 2] << 8) | data[temp_offset + 3];
        temp_offset += 4 + ext_data_len;
        ext_count++;
    }
    
    /* Allocate and parse extensions */
    fp->extensions = (uint16_t*)malloc(ext_count * sizeof(uint16_t));
    if (fp->extensions) {
        fp->extension_count = 0;
        while (offset + 4 <= length && offset < temp_offset) {
            fp->extensions[fp->extension_count] = (data[offset] << 8) | data[offset + 1];
            uint16_t ext_data_len = (data[offset + 2] << 8) | data[offset + 3];
            offset += 4 + ext_data_len;
            fp->extension_count++;
        }
    }
    
    return true;
}

/* Compute JA3 hash from fingerprint data */
void tls_compute_ja3(TLSFingerprint* fp) {
    if (!fp) return;
    
    /* Build JA3 string: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats */
    char ja3_string[4096];
    int pos = 0;
    
    /* TLS version */
    pos += snprintf(ja3_string + pos, sizeof(ja3_string) - pos, "%d,", fp->tls_version);
    
    /* Cipher suites (skip GREASE values) */
    for (uint32_t i = 0; i < fp->cipher_count; i++) {
        uint16_t cipher = fp->cipher_suites[i];
        /* Skip GREASE values */
        if ((cipher & 0x0f0f) == 0x0a0a) continue;
        if (i > 0) pos += snprintf(ja3_string + pos, sizeof(ja3_string) - pos, "-");
        pos += snprintf(ja3_string + pos, sizeof(ja3_string) - pos, "%d", cipher);
    }
    pos += snprintf(ja3_string + pos, sizeof(ja3_string) - pos, ",");
    
    /* Extensions (skip GREASE values) */
    for (uint32_t i = 0; i < fp->extension_count; i++) {
        uint16_t ext = fp->extensions[i];
        if ((ext & 0x0f0f) == 0x0a0a) continue;
        if (i > 0) pos += snprintf(ja3_string + pos, sizeof(ja3_string) - pos, "-");
        pos += snprintf(ja3_string + pos, sizeof(ja3_string) - pos, "%d", ext);
    }
    pos += snprintf(ja3_string + pos, sizeof(ja3_string) - pos, ",,");  /* Empty curves and point formats */
    
    /* Compute MD5 hash */
    MD5_CTX ctx;
    uint8_t digest[16];
    md5_init(&ctx);
    md5_update(&ctx, (uint8_t*)ja3_string, (uint32_t)strlen(ja3_string));
    md5_final(digest, &ctx);
    
    /* Convert to hex string */
    for (int i = 0; i < 16; i++) {
        snprintf(&fp->ja3_hash[i * 2], 3, "%02x", digest[i]);
    }
}

/* Check if JA3 hash is blocked */
bool tls_is_blocked(TLSFingerprinter* fp, const char* ja3_hash) {
    if (!fp || !ja3_hash) return false;
    
    ng_mutex_lock(&fp->mutex);
    
    for (uint32_t i = 0; i < fp->blocked_count; i++) {
        if (strcmp(fp->blocked_hashes[i], ja3_hash) == 0) {
            ng_mutex_unlock(&fp->mutex);
            return true;
        }
    }
    
    ng_mutex_unlock(&fp->mutex);
    return false;
}

/* Block a JA3 hash */
void tls_block_hash(TLSFingerprinter* fp, const char* ja3_hash, const char* description) {
    if (!fp || !ja3_hash) return;
    
    ng_mutex_lock(&fp->mutex);
    
    /* Expand if needed */
    if (fp->blocked_count >= fp->blocked_capacity) {
        uint32_t new_cap = fp->blocked_capacity * 2;
        char** new_hashes = (char**)realloc(fp->blocked_hashes, new_cap * sizeof(char*));
        char** new_descs = (char**)realloc(fp->blocked_descriptions, new_cap * sizeof(char*));
        
        if (!new_hashes || !new_descs) {
            ng_mutex_unlock(&fp->mutex);
            return;
        }
        
        fp->blocked_hashes = new_hashes;
        fp->blocked_descriptions = new_descs;
        fp->blocked_capacity = new_cap;
    }
    
    /* Add entry */
    fp->blocked_hashes[fp->blocked_count] = _strdup(ja3_hash);
    fp->blocked_descriptions[fp->blocked_count] = description ? _strdup(description) : NULL;
    fp->blocked_count++;
    
    ng_mutex_unlock(&fp->mutex);
}

/* API Functions */
NETGUARD_API NetGuardError netguard_get_ja3(uint64_t flow_hash, TLSFingerprint* fingerprint) {
    /* This would require storing JA3 data per flow - simplified implementation */
    (void)flow_hash;
    (void)fingerprint;
    return NETGUARD_ERROR_INVALID_PARAM;
}

NETGUARD_API bool netguard_is_ja3_blocked(const char* ja3_hash) {
    if (!g_engine.tls_fingerprinter) return false;
    return tls_is_blocked(g_engine.tls_fingerprinter, ja3_hash);
}

NETGUARD_API NetGuardError netguard_block_ja3(const char* ja3_hash, const char* description) {
    if (!g_engine.tls_fingerprinter || !ja3_hash) {
        return NETGUARD_ERROR_INVALID_PARAM;
    }
    tls_block_hash(g_engine.tls_fingerprinter, ja3_hash, description);
    return NETGUARD_OK;
}
