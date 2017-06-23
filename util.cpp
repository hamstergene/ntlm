#include "util.h"

std::string to_uppercase(const std::string& s)
{
    if(s.length() == 0){
		return std::string("");
	}
	char* buf = new char[s.length()];
	s.copy(buf, s.length());
	for(unsigned int i = 0; i < s.length(); i++)
		buf[i] = static_cast<char>(toupper(buf[i]));
	std::string r(buf, s.length());
	delete [] buf;
	return r;
}

bool is_big_endian()
{
	uint32_t data = 0x11223344;
	uint8_t* pdata = (uint8_t*)&data;
	return pdata[0] == 0x11;
}

uint16_t to_little_endian(uint16_t i_data)
{
	if(!is_big_endian())
	{
		return i_data;
	}
	uint16_t o_data;
	uint8_t* pi = (uint8_t*)&i_data;
	uint8_t* po = (uint8_t*)&o_data;
	
	po[0] = pi[1];
	po[1] = pi[0];
	return o_data;
}

uint32_t to_little_endian(uint32_t i_data)
{
	if(!is_big_endian())
	{
		return i_data;
	}
	uint32_t o_data;
	uint8_t* pi = (uint8_t*)&i_data;
	uint8_t* po = (uint8_t*)&o_data;
	
	po[0] = pi[3];
	po[1] = pi[2];
	po[2] = pi[1];
	po[3] = pi[0];
	return o_data;
}

uint64_t to_little_endian(uint64_t i_data)
{
    if(!is_big_endian())
	{
		return i_data;
	}
	uint64_t o_data;
	uint8_t* pi = (uint8_t*)&i_data;
	uint8_t* po = (uint8_t*)&o_data;
	
	size_t i = 0;
	for(i = 0; i < 8; ++i)
	{
	    po[i] = pi[7 - i];
	}
	
	return o_data;
}

void setup_des_key(unsigned char key_56[], DES_key_schedule &ks) {
	DES_cblock key;

	key[0] = key_56[0];
	key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
	key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
	key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
	key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
	key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
	key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
	key[7] =  (key_56[6] << 1) & 0xFF;

	DES_set_odd_parity(&key);
	DES_set_key(&key, &ks);
}

void des_enc(uint8_t* key, DES_cblock* data, DES_cblock* result)
{
    DES_key_schedule ks;
    setup_des_key(key, ks);
    DES_ecb_encrypt(data, result, &ks, DES_ENCRYPT);
}

void md4_enc(uint8_t* data, size_t data_len, uint8_t* result)
{
    MD4(data, data_len, result);
}

void md5_enc(uint8_t* data, size_t data_len, uint8_t* result)
{
    MD5(data, data_len, result);  
}

void hmac_md5_enc(void* key, int key_len, uint8_t* data, int data_len, uint8_t* digest, unsigned int digest_len)
{
    HMAC_CTX * hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, key, key_len, EVP_md5(), NULL);
    HMAC_Update(hmac_ctx, data, data_len);
    HMAC_Final(hmac_ctx, digest, &digest_len);
    HMAC_CTX_free(hmac_ctx);
}

void ascii_to_unicode(std::string ascii_str, char *unicode_str)
{
	for (size_t i = 0; i < ascii_str.length(); i++) {
		unicode_str[2*i] = ASCII_CHAR(ascii_str[i]);
		unicode_str[2*i +1] = '\0';
	}
}

void concat(const uint8_t* data1, size_t data1_len, const uint8_t* data2, size_t data2_len, uint8_t* result)
{
    memmove(result, data1, data1_len);
    memmove(result + data1_len, data2, data2_len);
}

uint64_t create_timestamp()
{
    /*
    * calc Timestamp
    * the windows epoch starts 1601-01-01T00:00:00Z. It's 11644473600 seconds before the UNIX/Linux epoch (1970-01-01T00:00:00Z). The Windows ticks are in 100 nanoseconds. 
    */	
    uint64_t windows_tick = 10000000;
    uint64_t win_unix_time_diff = 11644473600ULL;
    uint64_t timestamp;
    time_t cur = time(NULL);
    uint64_t win_cur = cur + win_unix_time_diff;
    timestamp = (uint64_t) win_cur * windows_tick;
    
    if(is_big_endian())
    {
        timestamp = to_little_endian(timestamp);
    }
    
    return timestamp;
}

size_t base64_decode(const char *src, uint8_t *dst) {
    BIO *bio, *b64;

    bio = BIO_new_mem_buf(src, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    size_t decode_len = BIO_read(bio, (void*)dst, strlen(src));
    BIO_free_all(bio);
    return decode_len;
}

void base64_encode (const char *src, char *dst, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *result;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    BIO_write(bio, src, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &result);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    memmove(dst, (*result).data, (*result).length);
    BUF_MEM_free(result);
}
