#ifndef	__NTLM_UTIL_INCLUDE
#define	__NTLM_UTIL_INCLUDE
#include <string>
#include "openssl/des.h"
#include "openssl/md4.h"
#include "openssl/md5.h"
#include "openssl/hmac.h"
#include "openssl/buffer.h"
#include <cstring>
using namespace std;

#define ASCII_CHAR(ch)  (ch)
#define ASCII_STR(s) (s)
#define BASE64_ENCODE_LENGTH(len)	(4 * (((len) + 2) / 3))
#define BASE64_DECODE_LENGTH(len)	(3 * (((len) + 3) / 4))

typedef unsigned char byte;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

string to_uppercase(const string& s);

bool is_big_endian();
uint16_t to_little_endian(uint16_t i_data);
uint32_t to_little_endian(uint32_t i_data);
uint64_t to_little_endian(uint64_t i_data);


void des_enc(byte* key, DES_cblock* data, DES_cblock* result);
void md4_enc(byte* data, size_t data_len, byte* result);
void md5_enc(byte* data, size_t data_len, byte* result);
void hmac_md5_enc(void* key, int key_len, byte* data, int data_len, byte* digest, unsigned int digest_len);

void ascii_to_unicode(string ascii_str, char *unicode_str);
void concat(const byte* data1, size_t data1_len, const byte* data2, size_t data2_len, byte* result);
uint64_t create_timestamp();


void base64_encode(const char *src, char *dst, size_t length);

size_t base64_decode(const char *src, byte *dst);
#endif