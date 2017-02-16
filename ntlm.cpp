#include "ntlm.h"
#include "openssl/rand.h"
#include <cstring>
#include <stdio.h>
#include <strings.h>

string make_type1_msg(string domain, string host, int ntlm_resp_type)
{
    string upper_domain = to_uppercase(domain);
    string upper_host = to_uppercase(host);
    size_t dom_len = upper_domain.length();
    size_t hst_len = upper_host.length();    
    
    struct Type1Message msg1;
    
    strcpy(msg1.signature, ASCII_STR(NTLMSSP_SIGNATURE));
    
    msg1.type = to_little_endian((uint32_t) TYPE1_INDICATOR);
    
    if( USE_NTLMV1 == ntlm_resp_type)
        msg1.flag = to_little_endian((uint32_t) NTLMV1_FLAG);
    else if( USE_NTLM2SESSION == ntlm_resp_type)
        msg1.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
    else if (USE_NTLMV2 == ntlm_resp_type)
        msg1.flag = to_little_endian((uint32_t) NTLMV2_FLAG);
    else
        return "";
        
        
    msg1.dom_len = msg1.dom_max_len =to_little_endian((uint16_t) dom_len);
    msg1.dom_off = to_little_endian((uint32_t) MSG1_SIZE);
    
    msg1.hst_len = msg1.hst_max_len = to_little_endian((uint16_t) hst_len);
    msg1.hst_off  = to_little_endian((uint32_t)(MSG1_SIZE + dom_len));
    
    size_t buff_size = MSG1_SIZE + dom_len + hst_len;
    char *buff = NULL;
    buff = new char[buff_size];
    bzero(buff, buff_size);
    memmove(buff, &msg1, MSG1_SIZE);
    if(0 != dom_len)
    	memmove(buff + MSG1_SIZE, ASCII_STR(upper_domain.c_str()), dom_len);
    if(0 != hst_len)
	    memmove(buff + MSG1_SIZE + dom_len, ASCII_STR(upper_host.c_str()), hst_len);

    
    size_t base64_len = BASE64_ENCODE_LENGTH(buff_size) + 1;
    char *buff_base64 = new char[base64_len];
    bzero(buff_base64, base64_len);
    base64_encode(buff, buff_base64, buff_size);
    buff_base64[base64_len] = '\0';
    string result(buff_base64);
    
    delete []buff;
	delete []buff_base64;
	
	return result;
}

string make_type3_msg(string username, string password, string domain, string host, string msg2_b64_buff, int ntlm_resp_type)
{
    if(0 == msg2_b64_buff.length())
    {
        return "";
    }
    Message2Handle msg2_handle(msg2_b64_buff);
    
    bool support_unicode = msg2_handle.support_unicode();
    
    struct Type3Message msg3;
    uint16_t lm_challenge_resp_len, nt_challenge_resp_len, dom_len, usr_name_len, hst_len;
    uint32_t lm_challenge_resp_off, nt_challenge_resp_off, dom_off, usr_name_off, hst_off;
        
    strcpy(msg3.signature, ASCII_STR(NTLMSSP_SIGNATURE));
    msg3.type = to_little_endian((uint32_t) TYPE3_INDICATOR);
    
    byte lm_resp[24];
    byte* ntlm_resp = new byte[24];
    setup_security_buffer(lm_challenge_resp_len, lm_challenge_resp_off, msg3.lm_challenge_resp_len, msg3.lm_challenge_resp_max_len, msg3.lm_challenge_resp_off, 
            24, 
            MSG3_SIZE);
        
    setup_security_buffer(dom_len, dom_off, msg3.dom_len, msg3.dom_max_len, msg3.dom_off, 
        support_unicode ? 2*(uint16_t) domain.length() : (uint16_t) domain.length(), 
        lm_challenge_resp_off + lm_challenge_resp_len);
    
    setup_security_buffer(usr_name_len, usr_name_off, msg3.usr_name_len, msg3.usr_name_max_len, msg3.usr_name_off, 
        support_unicode ? 2*(uint16_t) username.length() : (uint16_t) username.length(), 
        dom_off + dom_len);
    
    setup_security_buffer(hst_len, hst_off, msg3.hst_len, msg3.hst_max_len, msg3.hst_off, 
        support_unicode ? 2*(uint16_t) host.length() : (uint16_t) host.length(), 
        usr_name_off + usr_name_len);
        
    setup_security_buffer(nt_challenge_resp_len, nt_challenge_resp_off, msg3.nt_challenge_resp_len, msg3.nt_challenge_resp_max_len, msg3.nt_challenge_resp_off, 
            24, 
            hst_off + hst_len);

    msg3.session_key_len = msg3.session_key_max_len = 0;

    if( USE_NTLMV1 == ntlm_resp_type)
    {
        msg3.flag = to_little_endian((uint32_t) NTLMV1_FLAG);

        bzero(lm_resp, 24);
        calc_lmv1_resp(password, msg2_handle.get_challenge(), lm_resp);
        
        byte *ntlmv1_resp = ntlm_resp;
        bzero(ntlmv1_resp, 24);
        calc_ntlmv1_resp(password, msg2_handle.get_challenge(), ntlmv1_resp);
        
    }else if( USE_NTLM2SESSION == ntlm_resp_type)
    {
        msg3.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
        
        byte* ntlm2session_resp = ntlm_resp;
        bzero(lm_resp, 24);
        bzero(ntlm2session_resp, 24);
        
        byte client_nonce[8];
        bzero(client_nonce, 8);
        create_client_nonce(client_nonce, 8);
        calc_ntlm2session_resp(password, msg2_handle.get_challenge(), client_nonce, lm_resp, ntlm2session_resp);
        
    }else if( USE_NTLMV2 == ntlm_resp_type)
    {

        msg3.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
        byte* lmv2_resp = lm_resp;
        bzero(lmv2_resp, 24);
        calc_lmv2_resp(username, password, domain, msg2_handle.get_challenge(), lmv2_resp);
        
        
        uint16_t target_info_len = 0;
        const byte* target_info = msg2_handle.get_target_info(target_info_len);
        size_t blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
        size_t ntlmv2_resp_len = 16 + blob_len;// hmac + blob
        byte *ntlmv2_resp = new byte[ntlmv2_resp_len];
        ntlm_resp = ntlmv2_resp;
        bzero(ntlmv2_resp, ntlmv2_resp_len);
        
        setup_security_buffer(nt_challenge_resp_len, nt_challenge_resp_off, msg3.nt_challenge_resp_len, msg3.nt_challenge_resp_max_len, msg3.nt_challenge_resp_off, 
            ntlmv2_resp_len, 
            hst_off + hst_len);
        calc_ntlmv2_resp(username, password, domain, msg2_handle.get_challenge(), target_info, target_info_len, ntlmv2_resp);
        
    }else
    {
        return "";
    }
    
    size_t msg3_buff_len = MSG3_SIZE + lm_challenge_resp_len + nt_challenge_resp_len + dom_len + usr_name_len + hst_len;
    char* msg3_buff = new char[msg3_buff_len];
    memmove(msg3_buff, &msg3, MSG3_SIZE);
    memmove(msg3_buff + lm_challenge_resp_off, lm_resp, lm_challenge_resp_len);
    memmove(msg3_buff + nt_challenge_resp_off, ntlm_resp, nt_challenge_resp_len);

    char* p_domain = (char*)domain.c_str();
    char* p_username = (char*)username.c_str();
    char* p_host = (char*)host.c_str();
    if(support_unicode)
    {
        p_domain = new char[dom_len];
        p_username = new char[usr_name_len];
        p_host = new char[hst_len];
        
        bzero(p_domain, dom_len);
        bzero(p_username, usr_name_len);
        bzero(p_host, hst_len);
        
        ascii_to_unicode(domain, p_domain);
        ascii_to_unicode(username, p_username);
        ascii_to_unicode(host, p_host);
    }
    memmove(msg3_buff + dom_off, p_domain, dom_len);
    memmove(msg3_buff + usr_name_off, p_username, usr_name_len);
    memmove(msg3_buff + hst_off, p_host, hst_len);

    if(support_unicode)
    {
        delete [] p_domain;
        delete [] p_username;
        delete [] p_host;
    }

    char *msg3_buff_b64 = new char[BASE64_ENCODE_LENGTH(msg3_buff_len) + 1];
    base64_encode(msg3_buff, msg3_buff_b64, msg3_buff_len);
    msg3_buff_b64[BASE64_ENCODE_LENGTH(msg3_buff_len)] = '\0';
    string result(msg3_buff_b64);

    delete [] msg3_buff;
    delete [] msg3_buff_b64;
    delete [] ntlm_resp;
    return result;
    
}

void calc_lmv1_resp(string password, const byte* challenge, byte* lm_resp)
{
    string upper_pwd = to_uppercase(password);
    size_t upper_pwd_len = upper_pwd.length();
    byte pwd[14];
    bzero(pwd, 14);
    size_t mv_len = upper_pwd_len < 14 ? upper_pwd_len : 14;
    memmove(pwd, upper_pwd.c_str(), mv_len);
    byte* pwd_l = pwd;// low 7 bytes
    byte* pwd_h = pwd + 7;// high 7 bytes
    
    byte lm_hash_padded[21];
    bzero(lm_hash_padded, 21);
    
    byte* lm_hash_l = lm_hash_padded;// low 8 bytes
    byte* lm_hash_h = lm_hash_padded + 8; // high 8 bytes
    byte* lm_hash_p = lm_hash_padded + 16; // the padded 5 bytes
    DES_cblock magic = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 }; //KGS!@$%
    
    //key data result
    des_enc(pwd_l, &magic, (DES_cblock*)lm_hash_l);
    des_enc(pwd_h, &magic, (DES_cblock*)lm_hash_h);
    bzero(lm_hash_p, 5);
    
    bzero(lm_resp, 24);
    byte* lm_resp1 = lm_resp;
    byte* lm_resp2 = lm_resp + 8;
    byte* lm_resp3 = lm_resp + 16;
    
    byte* lm_hash_padded1 = lm_hash_padded;
    byte* lm_hash_padded2 = lm_hash_padded + 7;
    byte* lm_hash_padded3 = lm_hash_padded + 14;

    des_enc(lm_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) lm_resp1);
    des_enc(lm_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) lm_resp2);
    des_enc(lm_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) lm_resp3);
    
}

void calc_ntlmv1_resp(string password, const byte* challenge, byte* ntlmv1_resp)
{
    byte ntlmv1_hash_padded[21];
    bzero(ntlmv1_hash_padded, 21);
    bzero(ntlmv1_resp, 24);
    
    byte ntlmv1_hash[MD4_DIGEST_LENGTH]; // 16-byte
    bzero(ntlmv1_hash, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password, ntlmv1_hash);
    
    bzero(ntlmv1_hash_padded, 21);
    memmove(ntlmv1_hash_padded, ntlmv1_hash, MD4_DIGEST_LENGTH);
    
    byte* ntlmv1_resp1 = ntlmv1_resp;
    byte* ntlmv1_resp2 = ntlmv1_resp + 8;
    byte* ntlmv1_resp3 = ntlmv1_resp + 16;
    
    byte* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    byte* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    byte* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp3);
    
}

void calc_ntlm2session_resp(string password, const byte* challenge, byte* client_nonce, byte* lm_resp, byte* ntlm2session_resp)
{
    bzero(lm_resp, 24);
    memmove(lm_resp, client_nonce, 8);
        
    byte session_nonce[16];
    bzero(session_nonce, 16);
    concat(challenge, 8, client_nonce, 8, session_nonce);
    
    byte ntlm2session_hash[8];
    bzero(ntlm2session_hash, 8);
    calc_ntlm2session_hash(session_nonce, ntlm2session_hash);
    
    
    byte ntlmv1_hash_padded[21];
    bzero(ntlmv1_hash_padded, 21);

    byte ntlmv1_hash[MD4_DIGEST_LENGTH]; // 16-byte
    bzero(ntlmv1_hash, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password, ntlmv1_hash);
    
    bzero(ntlmv1_hash_padded, 21);
    memmove(ntlmv1_hash_padded, ntlmv1_hash, MD4_DIGEST_LENGTH);
    
    byte* ntlm2session_resp1 = ntlm2session_resp;
    byte* ntlm2session_resp2 = ntlm2session_resp + 8;
    byte* ntlm2session_resp3 = ntlm2session_resp + 16;
    
    byte* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    byte* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    byte* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp3);
}

void calc_lmv2_resp(string username, string password, string domain, const byte* challenge, byte* lmv2_resp)
{
    
    byte client_nonce[8];
    bzero(client_nonce, 8);
    create_client_nonce(client_nonce, 8);

    byte data[16];
    bzero(data, 16);
    concat(client_nonce, 8, challenge, 8, data);
    
    byte ntlmv2_hash[16];
    bzero(ntlmv2_hash, 16);
    calc_ntlmv2_hash(username, password, domain, ntlmv2_hash);
    
    byte hmac[16];
    bzero(hmac,16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data, 16, hmac, 16);
    
    concat(hmac, 16, client_nonce, 8, lmv2_resp);
}

void calc_ntlmv2_resp(string username, string password, string domain, const byte* challenge, const byte* target_info, uint16_t target_info_len, byte* ntlmv2_resp)
{

    size_t blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
    byte* blob = new byte[blob_len];
    bzero(blob, blob_len);
    create_blob(target_info, target_info_len, blob, blob_len);
    
    size_t challenge_len = 8;
    size_t data_len = challenge_len + blob_len;
    byte* data = new byte[data_len];
    concat(challenge, challenge_len, blob, blob_len, data);
    
    byte ntlmv2_hash[16];
    bzero(ntlmv2_hash, 16);
    calc_ntlmv2_hash(username, password, domain, ntlmv2_hash);
    
    byte hmac[16];
    bzero(hmac,16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data, data_len, hmac, 16);

    concat(hmac, 16, blob, blob_len, ntlmv2_resp); 
    delete [] blob;   
}

void calc_ntlmv1_hash(string password, byte* ntlmv1_hash)
{
    bzero(ntlmv1_hash, MD4_DIGEST_LENGTH);
    size_t unicode_pwd_len = password.length() *2;
    char* unicode_pwd = new char[unicode_pwd_len];
    
    ascii_to_unicode(password, unicode_pwd);
    
    md4_enc((byte*)unicode_pwd, unicode_pwd_len, ntlmv1_hash);

    delete []unicode_pwd;
}

//16-byte session_nonce
//8-byte session_hash
void calc_ntlm2session_hash(byte* session_nonce, byte* session_hash)
{
    //session_nonce is 16-byte
    //session_hash is 8 byte
    bzero(session_hash, 8);
    byte md5_nonce[16];
    md5_enc(session_nonce, 16, md5_nonce);
    memmove(session_hash, md5_nonce, 8);
}

void calc_ntlmv2_hash(string username, string password, string domain, byte* ntlmv2_hash)
{
    
    bzero(ntlmv2_hash, 16);
    
    byte ntlmv1_hash[MD4_DIGEST_LENGTH]; 
    bzero(ntlmv1_hash, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password, ntlmv1_hash);
    
    size_t unicode_name_dom_len = username.length() * 2 + domain.length() * 2;
    char* unicode_name_dom = new char[unicode_name_dom_len];
    
    ascii_to_unicode(to_uppercase(username), unicode_name_dom);
    ascii_to_unicode(domain, unicode_name_dom + username.length() * 2);
    
    hmac_md5_enc((void*)ntlmv1_hash, MD4_DIGEST_LENGTH, (byte*)unicode_name_dom, unicode_name_dom_len, ntlmv2_hash, 16);
    
    delete [] unicode_name_dom;
    
}

void create_client_nonce(byte* nonce, size_t len)
{
    bzero(nonce, len);
    if(8 != len)
    {
        return;
    }
	int ret = RAND_bytes(nonce, 8);
	//if fail, set 0xffffffff0102034
	if(ret != 1)
	{
        for(int i = 0; i < 4; ++i)
        {
        	nonce[i] = 0xff;
        }
        
        for(int j = 4; j < 8; ++j)
		{
			nonce[j] = j;
		}

	}
}

void create_blob(const byte* target_info, uint16_t target_info_len, byte* blob, size_t blob_len)
{
   /*
    * Description   Content
    * 0             Blob Signature      0x01010000
    * 4             Reserved            long (0x00000000)
    * 8             Timestamp           Little-endian, 64-bit signed value representing the number of tenths of a microsecond since January 1, 1601.
    * 16            Client Nonce        8 bytes
    * 24            Unknown             4 bytes
    * 28            Target Information  Target Information block (from the Type 2 message).
    * (variable)    Unknown             4 bytes
    */
    bzero(blob, blob_len);
    if (28 + target_info_len != blob_len)
    {
        return;
    }

    unsigned long long timestamp = create_timestamp();
    byte client_nonce[8];
    bzero(client_nonce, 8);
    create_client_nonce(client_nonce, 8);
    
    //byte *blob = new byte[blob_len];
    bzero(blob, blob_len);
    blob[0] = 0x1;
    blob[1] = 0x1;
    memmove(blob + 8, &timestamp, 8);
    memmove(blob + 16, client_nonce, 8);
    memmove(blob + 28, target_info, target_info_len);
}

void setup_security_buffer(uint16_t &temp_len,uint32_t &temp_off, uint16_t &msg_len, uint16_t &msg_max_len, uint32_t &msg_off, uint16_t len_val, uint32_t off_val)
{
    temp_len = len_val;
    temp_off = off_val;
    msg_len = msg_max_len = to_little_endian(len_val);
    msg_off = to_little_endian(off_val);
}


Message2Handle::Message2Handle(const string & msg2_b64_buff)
{
    msg2_buff = NULL;
    size_t msg2_buff_len = BASE64_DECODE_LENGTH(msg2_b64_buff.length());
    msg2_buff = new byte[msg2_buff_len];    
    base64_decode(msg2_b64_buff.c_str(), msg2_buff);
    memmove(&msg2, msg2_buff, MSG2_SIZE);
}
Message2Handle::~Message2Handle()
{
    if(NULL != msg2_buff)
    {
        delete [] msg2_buff;
    }
}

const byte* Message2Handle::get_challenge()
{
    return msg2.challenge;
    return msg2.challenge;
}

uint32_t Message2Handle::get_flag()
{
    return msg2.flag;
}

bool Message2Handle::support_unicode()
{
    return msg2.flag & 0x1;
}

const byte* Message2Handle::get_target_info(uint16_t& target_info_len)
{
    target_info_len = msg2.target_info_len;
  
    const byte* target_info = (const byte*)( msg2_buff + msg2.target_info_off);
    return target_info;
}