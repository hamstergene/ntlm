#ifndef	__NTLM_UTIL_INCLUDE
#define	__NTLM_UTIL_INCLUDE
#include <string>
#include <cstring>
using namespace std;
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

extern "C" {
#include "libcrypto-compat.h"
}

#define ASCII_CHAR(ch)  (ch)
#define ASCII_STR(s) (s)
#define BASE64_ENCODE_LENGTH(len)	(4 * (((len) + 2) / 3))
#define BASE64_DECODE_LENGTH(len)	(3 * (((len) + 3) / 4))

std::string to_uppercase(const string& s);

bool is_big_endian();
uint16_t to_little_endian(uint16_t i_data);
uint32_t to_little_endian(uint32_t i_data);
uint64_t to_little_endian(uint64_t i_data);


void des_enc(uint8_t* key, DES_cblock* data, DES_cblock* result);
void md4_enc(uint8_t* data, size_t data_len, uint8_t* result);
void md5_enc(uint8_t* data, size_t data_len, uint8_t* result);
void hmac_md5_enc(void* key, int key_len, uint8_t* data, int data_len, uint8_t* digest, unsigned int digest_len);

void ascii_to_unicode(string ascii_str, char *unicode_str);
void concat(const uint8_t* data1, size_t data1_len, const uint8_t* data2, size_t data2_len, uint8_t* result);
uint64_t create_timestamp();


void base64_encode(const char *src, char *dst, size_t length);

size_t base64_decode(const char *src, uint8_t *dst);
#endif
