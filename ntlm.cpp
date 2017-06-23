#include <ntlm/ntlm.h>
#include "util.h"
#include <openssl/rand.h>
#include <cstring>

std::string make_type1_msg(std::string domain, std::string host, int ntlm_resp_type)
{
    std::string upper_domain = to_uppercase(domain);
    std::string upper_host = to_uppercase(host);
    size_t dom_len = upper_domain.length();
    size_t hst_len = upper_host.length();    
    
    struct Type1Message msg1;
    memset(&msg1, 0, MSG1_SIZE);
    
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
    memset(buff, 0, buff_size);
    memmove(buff, &msg1, MSG1_SIZE);
    if(0 != dom_len)
    	memmove(buff + MSG1_SIZE, ASCII_STR(upper_domain.c_str()), dom_len);
    if(0 != hst_len)
	    memmove(buff + MSG1_SIZE + dom_len, ASCII_STR(upper_host.c_str()), hst_len);

    
    size_t base64_len = BASE64_ENCODE_LENGTH(buff_size) + 1;
    char *buff_base64 = new char[base64_len];
    memset(buff_base64, 0, base64_len);
    base64_encode(buff, buff_base64, buff_size);
    buff_base64[base64_len - 1] = '\0';
    std::string result(buff_base64);
    
    delete []buff;
	delete []buff_base64;
	
	return result;
}

std::string make_type3_msg(std::string username, std::string password, std::string domain, std::string host, std::string msg2_b64_buff, int ntlm_resp_type)
{
    if(0 == msg2_b64_buff.length())
    {
        return "";
    }
    Message2Handle msg2_handle(msg2_b64_buff);
    
    bool support_unicode = msg2_handle.support_unicode();
    
    struct Type3Message msg3;
    memset(&msg3, 0, MSG3_SIZE);
    uint16_t lm_challenge_resp_len, nt_challenge_resp_len, dom_len, usr_name_len, hst_len;
    uint32_t lm_challenge_resp_off, nt_challenge_resp_off, dom_off, usr_name_off, hst_off;
        
    strcpy(msg3.signature, ASCII_STR(NTLMSSP_SIGNATURE));
    msg3.type = to_little_endian((uint32_t) TYPE3_INDICATOR);
    
    uint8_t lm_resp[24];
    uint8_t* ntlm_resp = new uint8_t[24];
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

        memset(lm_resp, 0, 24);
        calc_lmv1_resp(password, msg2_handle.get_challenge(), lm_resp);
        
        uint8_t *ntlmv1_resp = ntlm_resp;
        memset(ntlmv1_resp, 0, 24);
        calc_ntlmv1_resp(password, msg2_handle.get_challenge(), ntlmv1_resp);
        
    }else if( USE_NTLM2SESSION == ntlm_resp_type)
    {
        msg3.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
        
        uint8_t* ntlm2session_resp = ntlm_resp;
        memset(lm_resp, 0, 24);
        memset(ntlm2session_resp, 0, 24);
        
        uint8_t client_nonce[8];
        memset(client_nonce, 0, 8);
        create_client_nonce(client_nonce, 8);
        calc_ntlm2session_resp(password, msg2_handle.get_challenge(), client_nonce, lm_resp, ntlm2session_resp);
        
    }else if( USE_NTLMV2 == ntlm_resp_type)
    {

        msg3.flag = to_little_endian((uint32_t) NTLM2SESSION_FLAG);
        uint8_t* lmv2_resp = lm_resp;
        memset(lmv2_resp, 0, 24);
        calc_lmv2_resp(username, password, domain, msg2_handle.get_challenge(), lmv2_resp);
        
        
        uint16_t target_info_len = 0;
        const uint8_t* target_info = msg2_handle.get_target_info(target_info_len);
        size_t blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
        size_t ntlmv2_resp_len = 16 + blob_len;// hmac + blob
        uint8_t *ntlmv2_resp = new uint8_t[ntlmv2_resp_len];
        ntlm_resp = ntlmv2_resp;
        memset(ntlmv2_resp, 0, ntlmv2_resp_len);
        
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
        
        memset(p_domain, 0, dom_len);
        memset(p_username, 0, usr_name_len);
        memset(p_host, 0, hst_len);
        
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
    std::string result(msg3_buff_b64);

    delete [] msg3_buff;
    delete [] msg3_buff_b64;
    delete [] ntlm_resp;
    return result;
    
}

void calc_lmv1_resp(std::string password, const uint8_t* challenge, uint8_t* lm_resp)
{
    std::string upper_pwd = to_uppercase(password);
    size_t upper_pwd_len = upper_pwd.length();
    uint8_t pwd[14];
    memset(pwd, 0, 14);
    size_t mv_len = upper_pwd_len < 14 ? upper_pwd_len : 14;
    memmove(pwd, upper_pwd.c_str(), mv_len);
    uint8_t* pwd_l = pwd;// low 7 bytes
    uint8_t* pwd_h = pwd + 7;// high 7 bytes
    
    uint8_t lm_hash_padded[21];
    memset(lm_hash_padded, 0, 21);
    
    uint8_t* lm_hash_l = lm_hash_padded;// low 8 bytes
    uint8_t* lm_hash_h = lm_hash_padded + 8; // high 8 bytes
    uint8_t* lm_hash_p = lm_hash_padded + 16; // the padded 5 bytes
    DES_cblock magic = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 }; //KGS!@$%
    
    //key data result
    des_enc(pwd_l, &magic, (DES_cblock*)lm_hash_l);
    des_enc(pwd_h, &magic, (DES_cblock*)lm_hash_h);
    memset(lm_hash_p, 0, 5);
    
    memset(lm_resp, 0, 24);
    uint8_t* lm_resp1 = lm_resp;
    uint8_t* lm_resp2 = lm_resp + 8;
    uint8_t* lm_resp3 = lm_resp + 16;
    
    uint8_t* lm_hash_padded1 = lm_hash_padded;
    uint8_t* lm_hash_padded2 = lm_hash_padded + 7;
    uint8_t* lm_hash_padded3 = lm_hash_padded + 14;

    des_enc(lm_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) lm_resp1);
    des_enc(lm_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) lm_resp2);
    des_enc(lm_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) lm_resp3);
    
}

void calc_ntlmv1_resp(std::string password, const uint8_t* challenge, uint8_t* ntlmv1_resp)
{
    uint8_t ntlmv1_hash_padded[21];
    memset(ntlmv1_hash_padded, 0, 21);
    memset(ntlmv1_resp, 0, 24);
    
    uint8_t ntlmv1_hash[MD4_DIGEST_LENGTH]; // 16-uint8_t
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password, ntlmv1_hash);
    
    memset(ntlmv1_hash_padded, 0, 21);
    memmove(ntlmv1_hash_padded, ntlmv1_hash, MD4_DIGEST_LENGTH);
    
    uint8_t* ntlmv1_resp1 = ntlmv1_resp;
    uint8_t* ntlmv1_resp2 = ntlmv1_resp + 8;
    uint8_t* ntlmv1_resp3 = ntlmv1_resp + 16;
    
    uint8_t* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    uint8_t* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    uint8_t* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) challenge, (DES_cblock*) ntlmv1_resp3);
    
}

void calc_ntlm2session_resp(std::string password, const uint8_t* challenge, uint8_t* client_nonce, uint8_t* lm_resp, uint8_t* ntlm2session_resp)
{
    memset(lm_resp, 0, 24);
    memmove(lm_resp, client_nonce, 8);
        
    uint8_t session_nonce[16];
    memset(session_nonce, 0, 16);
    concat(challenge, 8, client_nonce, 8, session_nonce);
    
    uint8_t ntlm2session_hash[8];
    memset(ntlm2session_hash, 0, 8);
    calc_ntlm2session_hash(session_nonce, ntlm2session_hash);
    
    
    uint8_t ntlmv1_hash_padded[21];
    memset(ntlmv1_hash_padded, 0, 21);

    uint8_t ntlmv1_hash[MD4_DIGEST_LENGTH]; // 16-uint8_t
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password, ntlmv1_hash);
    
    memset(ntlmv1_hash_padded, 0, 21);
    memmove(ntlmv1_hash_padded, ntlmv1_hash, MD4_DIGEST_LENGTH);
    
    uint8_t* ntlm2session_resp1 = ntlm2session_resp;
    uint8_t* ntlm2session_resp2 = ntlm2session_resp + 8;
    uint8_t* ntlm2session_resp3 = ntlm2session_resp + 16;
    
    uint8_t* ntlmv1_hash_padded1 = ntlmv1_hash_padded;
    uint8_t* ntlmv1_hash_padded2 = ntlmv1_hash_padded  + 7;
    uint8_t* ntlmv1_hash_padded3 = ntlmv1_hash_padded  + 14;
    
    des_enc(ntlmv1_hash_padded1, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp1);
    des_enc(ntlmv1_hash_padded2, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp2);
    des_enc(ntlmv1_hash_padded3, (DES_cblock*) ntlm2session_hash, (DES_cblock*) ntlm2session_resp3);
}

void calc_lmv2_resp(std::string username, std::string password, std::string domain, const uint8_t* challenge, uint8_t* lmv2_resp)
{
    
    uint8_t client_nonce[8];
    memset(client_nonce, 0, 8);
    create_client_nonce(client_nonce, 8);

    uint8_t data[16];
    memset(data, 0, 16);
    concat(client_nonce, 8, challenge, 8, data);
    
    uint8_t ntlmv2_hash[16];
    memset(ntlmv2_hash, 0, 16);
    calc_ntlmv2_hash(username, password, domain, ntlmv2_hash);
    
    uint8_t hmac[16];
    memset(hmac, 0, 16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data, 16, hmac, 16);
    
    concat(hmac, 16, client_nonce, 8, lmv2_resp);
}

void calc_ntlmv2_resp(std::string username, std::string password, std::string domain, const uint8_t* challenge, const uint8_t* target_info, uint16_t target_info_len, uint8_t* ntlmv2_resp)
{

    size_t blob_len = 28 + target_info_len; //the blob fixed len + target_info_len
    uint8_t* blob = new uint8_t[blob_len];
    memset(blob, 0, blob_len);
    create_blob(target_info, target_info_len, blob, blob_len);
    
    size_t challenge_len = 8;
    size_t data_len = challenge_len + blob_len;
    uint8_t* data = new uint8_t[data_len];
    concat(challenge, challenge_len, blob, blob_len, data);
    
    uint8_t ntlmv2_hash[16];
    memset(ntlmv2_hash, 0, 16);
    calc_ntlmv2_hash(username, password, domain, ntlmv2_hash);
    
    uint8_t hmac[16];
    memset(hmac, 0, 16);
    hmac_md5_enc((void*)ntlmv2_hash, 16, data, data_len, hmac, 16);

    concat(hmac, 16, blob, blob_len, ntlmv2_resp); 
    delete [] blob;   
}

void calc_ntlmv1_hash(std::string password, uint8_t* ntlmv1_hash)
{
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    size_t unicode_pwd_len = password.length() *2;
    char* unicode_pwd = new char[unicode_pwd_len];
    
    ascii_to_unicode(password, unicode_pwd);
    
    md4_enc((uint8_t*)unicode_pwd, unicode_pwd_len, ntlmv1_hash);

    delete []unicode_pwd;
}

//16-uint8_t session_nonce
//8-uint8_t session_hash
void calc_ntlm2session_hash(uint8_t* session_nonce, uint8_t* session_hash)
{
    //session_nonce is 16-uint8_t
    //session_hash is 8 uint8_t
    memset(session_hash, 0, 8);
    uint8_t md5_nonce[16];
    md5_enc(session_nonce, 16, md5_nonce);
    memmove(session_hash, md5_nonce, 8);
}

void calc_ntlmv2_hash(std::string username, std::string password, std::string domain, uint8_t* ntlmv2_hash)
{
    
    memset(ntlmv2_hash, 0, 16);
    
    uint8_t ntlmv1_hash[MD4_DIGEST_LENGTH]; 
    memset(ntlmv1_hash, 0, MD4_DIGEST_LENGTH);
    calc_ntlmv1_hash(password, ntlmv1_hash);
    
    size_t unicode_name_dom_len = username.length() * 2 + domain.length() * 2;
    char* unicode_name_dom = new char[unicode_name_dom_len];
    
    ascii_to_unicode(to_uppercase(username), unicode_name_dom);
    ascii_to_unicode(domain, unicode_name_dom + username.length() * 2);
    
    hmac_md5_enc((void*)ntlmv1_hash, MD4_DIGEST_LENGTH, (uint8_t*)unicode_name_dom, unicode_name_dom_len, ntlmv2_hash, 16);
    
    delete [] unicode_name_dom;
    
}

void create_client_nonce(uint8_t* nonce, size_t len)
{
    memset(nonce, 0, len);
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

void create_blob(const uint8_t* target_info, uint16_t target_info_len, uint8_t* blob, size_t blob_len)
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
    memset(blob, 0, blob_len);
    if (28 + target_info_len != blob_len)
    {
        return;
    }

    uint64_t timestamp = create_timestamp();
    uint8_t client_nonce[8];
    memset(client_nonce, 0, 8);
    create_client_nonce(client_nonce, 8);
    
    //uint8_t *blob = new uint8_t[blob_len];
    memset(blob, 0, blob_len);
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


Message2Handle::Message2Handle(const std::string & msg2_b64_buff)
{
    memset(&msg2, 0, MSG2_SIZE);
    msg2_buff = NULL;
    size_t msg2_buff_len = BASE64_DECODE_LENGTH(msg2_b64_buff.length());
    msg2_buff = new uint8_t[msg2_buff_len];    
    base64_decode(msg2_b64_buff.c_str(), msg2_buff);
    memmove(&msg2, msg2_buff, MSG2_SIZE);
    /*
    * following is a tricky part
    * the memmove directly may cause:
    * some little endian data was recognized as big endian data in big endian machine
    * so,just call toLittleEndian() in TmAuDIUtil could solve
    */
    if(is_big_endian())
    {
        msg2.type = to_little_endian(msg2.type);
        msg2.target_name_len = to_little_endian(msg2.target_name_len);
        msg2.target_name_max_len = to_little_endian(msg2.target_name_max_len);
        msg2.target_name_off = to_little_endian(msg2.target_name_off);
        msg2.flag = to_little_endian(msg2.flag);
        msg2.target_info_len = to_little_endian(msg2.target_info_len);
        msg2.target_info_max_len = to_little_endian(msg2.target_info_max_len);
        msg2.target_info_off = to_little_endian(msg2.target_info_off);
    }
    
}
Message2Handle::~Message2Handle()
{
    if(NULL != msg2_buff)
    {
        delete [] msg2_buff;
    }
}

const uint8_t* Message2Handle::get_challenge()
{
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

const uint8_t* Message2Handle::get_target_info(uint16_t& target_info_len)
{
    target_info_len = msg2.target_info_len;
  
    const uint8_t* target_info = (const uint8_t*)( msg2_buff + msg2.target_info_off);
    return target_info;
}