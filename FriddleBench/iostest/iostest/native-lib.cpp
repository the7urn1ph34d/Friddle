#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <os/log.h>
#include <CommonCrypto/CommonCryptor.h>


#define OUTPUT_BUFFER_SIZE 2048

#define LOGI(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ##__VA_ARGS__)

static struct timespec g_source_start;
static struct timespec g_sink_start;




static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void base64_encode(const char *input, size_t input_len, char *output, size_t *output_len) {
    *output_len = 4 * ((input_len + 2) / 3);
    size_t i = 0, j = 0;
    while (i < input_len) {
        unsigned int a = i < input_len ? (unsigned char)input[i++] : 0;
        unsigned int b = i < input_len ? (unsigned char)input[i++] : 0;
        unsigned int c = i < input_len ? (unsigned char)input[i++] : 0;
        unsigned int triple = (a << 16) | (b << 8) | c;
        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = (i > input_len + 1) ? '=' : base64_table[(triple >> 6) & 0x3F];
        output[j++] = (i > input_len)     ? '=' : base64_table[triple & 0x3F];
    }
    output[j] = '\0';
}

void str_copy(const char *input, size_t input_len, char *output, size_t *output_len) {
    *output_len = input_len;
    memcpy(output, input, input_len);
    output[input_len] = '\0';
}

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   16
#define AES_NR         10

static const uint8_t sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t Rcon[11] = {
        0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};
static const uint8_t aes_key[AES_KEY_SIZE] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static void RotWord(uint8_t *word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

static void SubWord(uint8_t *word) {
    word[0] = sbox[word[0]];
    word[1] = sbox[word[1]];
    word[2] = sbox[word[2]];
    word[3] = sbox[word[3]];
}

static void KeyExpansion(const uint8_t *key, uint8_t *expandedKeys) {
    memcpy(expandedKeys, key, AES_KEY_SIZE);
    uint32_t bytesGenerated = AES_KEY_SIZE;
    uint32_t rconIteration = 1;
    uint8_t temp[4];

    while (bytesGenerated < AES_BLOCK_SIZE * (AES_NR + 1)) {
        for (int i = 0; i < 4; i++)
            temp[i] = expandedKeys[bytesGenerated - 4 + i];

        if (bytesGenerated % AES_KEY_SIZE == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[rconIteration++];
        }
        for (int i = 0; i < 4; i++) {
            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - AES_KEY_SIZE] ^ temp[i];
            bytesGenerated++;
        }
    }
}

static void AddRoundKey(uint8_t state[4][4], const uint8_t *roundKey) {
    for (int row = 0; row < 4; row++)
        for (int col = 0; col < 4; col++)
            state[row][col] ^= roundKey[col * 4 + row];
}

static void SubBytes(uint8_t state[4][4]) {
    for (int row = 0; row < 4; row++)
        for (int col = 0; col < 4; col++)
            state[row][col] = sbox[state[row][col]];
}

static void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    // Row 1: shift left by 1.
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    // Row 2: shift left by 2.
    uint8_t temp1 = state[2][0], temp2 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = temp1;
    state[2][3] = temp2;
    // Row 3: shift left by 3.
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

static uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void MixColumns(uint8_t state[4][4]) {
    for (int col = 0; col < 4; col++) {
        uint8_t a0 = state[0][col];
        uint8_t a1 = state[1][col];
        uint8_t a2 = state[2][col];
        uint8_t a3 = state[3][col];

        uint8_t r0 = xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3;
        uint8_t r1 = a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3;
        uint8_t r2 = a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3));
        uint8_t r3 = (a0 ^ xtime(a0)) ^ a1 ^ a2 ^ xtime(a3);

        state[0][col] = r0;
        state[1][col] = r1;
        state[2][col] = r2;
        state[3][col] = r3;
    }
}

static void AES_EncryptBlock(const uint8_t *in, uint8_t *out, const uint8_t *expandedKeys) {
    uint8_t state[4][4];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i % 4][i / 4] = in[i];
    }

    AddRoundKey(state, expandedKeys);

    for (int round = 1; round < AES_NR; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKeys + round * AES_BLOCK_SIZE);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKeys + AES_NR * AES_BLOCK_SIZE);

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        out[i] = state[i % 4][i / 4];
    }
}

static void cccrypt_encrypt(const char *input,
                          size_t input_len,
                          char *output,
                          size_t *output_len) {
    size_t numEncrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCEncrypt,                    
        kCCAlgorithmAES128,            
        kCCOptionPKCS7Padding |        
        kCCOptionECBMode,              
        aes_key,                       
        kCCKeySizeAES128,              
        NULL,                          
        input,                         
        input_len,                     
        output,                        
        OUTPUT_BUFFER_SIZE,            
        &numEncrypted                  
    );

    if (status == kCCSuccess) {
        *output_len = numEncrypted;
    } else {
        *output_len = 0;
        LOGI("cccrypt_encrypt failed, status=%d", status);
    }
}

void aes_encrypt(const char *input, size_t input_len, char *output, size_t *output_len) {
    uint8_t expandedKeys[AES_BLOCK_SIZE * (AES_NR + 1)];
    KeyExpansion(aes_key, expandedKeys);
//    usleep(1000000);
    size_t pad_len = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);
    if (pad_len == 0) pad_len = AES_BLOCK_SIZE;
    size_t total = input_len + pad_len;

    for (size_t off = 0; off < total; off += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            size_t idx = off + i;
            block[i] = (uint8_t)(idx < input_len ? (unsigned char)input[idx] : pad_len);
        }
        AES_EncryptBlock(block, (uint8_t*)(output + off), expandedKeys);
    }
    *output_len = total;
}

static void to_hex(const char *in, size_t in_len, char *out, size_t *out_len) {
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; ++i) {
        unsigned char byte = (unsigned char)in[i];
        out[i*2    ] = hex_digits[byte >> 4];
        out[i*2 + 1] = hex_digits[byte & 0x0F];
    }
    *out_len = in_len * 2;
    out[*out_len] = '\0';
}

static void source_mode(const char *in, size_t in_len,
                        char *out, size_t *out_len, int mode, bool fp_mode) {
    g_source_start.tv_sec = g_source_start.tv_nsec = 0;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &g_source_start);
    LOGI("mode=%d source start, in_len=%zu, fp_mode=%d", mode, in_len, fp_mode);

    // Always use real input data for processing (taint analysis needs to track real data)
    const char *data_to_process = in;
    LOGI("Using real input data for processing, fp_mode=%d", fp_mode);

    if (mode == 4) {
        char tmp[OUTPUT_BUFFER_SIZE];
        size_t tmp_len = 0;
        cccrypt_encrypt(data_to_process, in_len, tmp, &tmp_len);
        to_hex(tmp, tmp_len, out, out_len);
    }
    else if (mode == 3) {
        char tmp[OUTPUT_BUFFER_SIZE];
        size_t tmp_len = 0;
        aes_encrypt(data_to_process, in_len, tmp, &tmp_len);
        to_hex(tmp, tmp_len, out, out_len);
    }
    else {
        switch (mode) {
            case 1: str_copy(data_to_process, in_len, out, out_len);      break;
            case 2: base64_encode(data_to_process, in_len, out, out_len); break;
            default: str_copy(data_to_process, in_len, out, out_len);     break;
        }
    }

    // In FP mode, this processed data won't be used - clean buffer will be used instead

    LOGI("mode=%d source done, out_len=%zu, fp_mode=%d", mode, *out_len, fp_mode);
}

static void sink_mode(char *buf, size_t len, int mode) {
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &g_sink_start);

    long sec_diff  = g_sink_start.tv_sec  - g_source_start.tv_sec;
    long nsec_diff = g_sink_start.tv_nsec - g_source_start.tv_nsec;
    long us_from_sec = sec_diff * 1000000L;
    long elapsed_us  = us_from_sec + (nsec_diff / 1000L);

    LOGI("mode=%d source timestamp: sec=%ld, nsec=%ld",
         mode,
         g_source_start.tv_sec,
         g_source_start.tv_nsec);
    LOGI("mode=%d sink   timestamp: sec=%ld, nsec=%ld",
         mode,
         g_sink_start.tv_sec,
         g_sink_start.tv_nsec);
    LOGI("mode=%d timing diff: sec_diff=%ld, nsec_diff=%ld, us_from_sec=%ld, elapsed_us=%ld",
         mode, sec_diff, nsec_diff, us_from_sec, elapsed_us);

    const char *label =
        mode==1 ? "strcpy: "     :
        mode==2 ? "base64: "         :
        mode==3 ? "aes(self): "      :
        mode==4 ? "aes(lib): "   :
                   "unknown: ";

    LOGI("mode=%d sink start, elapsed_us=%ld", mode, elapsed_us);

    char prefix[80];
    int  p_len = snprintf(prefix, sizeof(prefix), "[%ldus] %s", elapsed_us, label);

    if (p_len + len < OUTPUT_BUFFER_SIZE) {
        memmove(buf + p_len, buf, len);
        memcpy(buf, prefix, p_len);
        len += p_len;
        buf[len] = '\0';
    } else {
        LOGI("mode=%d sink prefix overflow: p_len=%d, buf_len=%zu",
             mode, p_len, len);
    }

    char sample[65] = {0};
    for (size_t i = 0; i < len && i < 32; i++) {
        snprintf(sample + i*2, 3, "%02x", (unsigned char)buf[i]);
    }
    LOGI("mode=%d sink done, sample_hex=%s", mode, sample);
}

extern "C"
const char *nativeProcess(const char *input, int mode, bool falsePositiveMode) {
    static char s_out_buf[OUTPUT_BUFFER_SIZE];
    static char s_clean_buf[OUTPUT_BUFFER_SIZE];  // Clean buffer for FP mode
    size_t out_len = 0;
    size_t input_len = strlen(input);

    // Create clean data for FP mode
    if (falsePositiveMode) {
        memset(s_clean_buf, 'A', input_len);
        s_clean_buf[input_len] = '\0';
        LOGI("Created clean buffer at %p for FP mode", s_clean_buf);
    }

    g_source_start.tv_sec  = 0;
    g_source_start.tv_nsec = 0;
    g_sink_start.tv_sec = 0;
    g_sink_start.tv_nsec = 0;
    source_mode(input, input_len, s_out_buf, &out_len, mode, falsePositiveMode);
    
    // Choose which buffer to use for sink_mode and return
    char *result_buf = falsePositiveMode ? s_clean_buf : s_out_buf;
    size_t result_len = falsePositiveMode ? input_len : out_len;
    
    sink_mode(result_buf, result_len, mode);

    return result_buf;
}
