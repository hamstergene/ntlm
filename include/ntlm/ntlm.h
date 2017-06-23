#pragma once
// References
//  [1][MS-NLMP]
//  [2][http://davenport.sourceforge.net/ntlm.html]

#include <stdint.h>
#include <string>

// The negotiate message
struct Type1Message 
{
    char        signature[8];
    uint32_t    type;
    uint32_t    flag;
    
    // optional
    // domain security buffer
    uint16_t    dom_len;
    uint16_t    dom_max_len;
    uint32_t    dom_off;
    
    // optional
    // host security buffer
    uint16_t    hst_len;
    uint16_t    hst_max_len;
    uint32_t    hst_off;
    
    // optional
    uint8_t        version[8];
};

// The challenge message
struct Type2Message
{
    char        signature[8];
    uint32_t    type;
    
    // target name security buffer
    uint16_t    target_name_len;
    uint16_t    target_name_max_len;
    uint32_t    target_name_off;
    
    uint32_t    flag;
    uint8_t        challenge[8];
    
    // There is a description difference between [1] and [2]
    // In [1], this is an 8-uint8_t array whose elements MUST be zero when sent and MUST be ignored on receipt.
    // But in [2], seems it could be used when Negotiate Local Call is set.
    // Currently, I don't use it.
    uint8_t        reserved[8];
    
    // optional
    // target info security buffer
    uint16_t    target_info_len;
    uint16_t    target_info_max_len;
    uint32_t    target_info_off;
    
    // optional
    uint8_t        version[8];
};

// The response message
struct Type3Message
{
    char        signature[8];
    uint32_t    type;
    
    // LM/LMv2 response security buffer
    uint16_t    lm_challenge_resp_len;
    uint16_t    lm_challenge_resp_max_len;
    uint32_t    lm_challenge_resp_off;
    
    // NTLM/NTLMv2 response security buffer
    uint16_t    nt_challenge_resp_len;
    uint16_t    nt_challenge_resp_max_len;
    uint32_t    nt_challenge_resp_off;
    
    // domain security buffer unicode or ascii
    uint16_t    dom_len;
    uint16_t    dom_max_len;
    uint32_t    dom_off;
    
    // user name security buffer unicode or ascii
    uint16_t    usr_name_len;
    uint16_t    usr_name_max_len;
    uint32_t    usr_name_off;
    
    // host security buffer unicode or ascii
    uint16_t    hst_len;
    uint16_t    hst_max_len;
    uint32_t    hst_off;
    
    // optional
    // session key security buffer
    uint16_t    session_key_len;
    uint16_t    session_key_max_len;
    uint32_t    session_key_off;
    
    // optional
    uint32_t    flag;
    
    // optional
    uint8_t        version[8];   
};

class Message2Handle
{
public:
    Message2Handle(const std::string & msg2_b64_buff);
    ~Message2Handle();
    
    const uint8_t* get_challenge();
    uint32_t get_flag();
    bool support_unicode();
    const uint8_t* get_target_info(uint16_t& target_info_len);
private:
    Type2Message msg2;
    uint8_t* msg2_buff;
      
};
#define MSG1_SIZE	(sizeof(struct Type1Message))
#define MSG2_SIZE	(sizeof(struct Type2Message))
#define MSG3_SIZE	(sizeof(struct Type3Message))

#define NTLMSSP_SIGNATURE "NTLMSSP"
#define TYPE1_INDICATOR 0x1
#define TYPE3_INDICATOR 0x3

#define USE_NTLMV1  1
#define USE_NTLM2SESSION   2
#define USE_NTLMV2  3

// ntlmv1 flag
// Negotiate Unicode                (0x00000001) 
// Negotiate OEM                    (0x00000002) 
// Request Target                   (0x00000004) 
// Negotiate NTLM                   (0x00000200) 
// Negotiate Always Sign            (0x00008000) <- must set mentioned in [1]
#define NTLMV1_FLAG 0x8207

//Negotiate Extended Security       (0x00080000)
#define NTLM2SESSION_FLAG 0x88207

//Negotiate Target Info             (0x00800000) <-- this is sent by type2 msg indicates support v2
//we still keey the flag same as session
#define NTLMV2_FLAG 0x88207

std::string make_type1_msg(std::string domain, std::string host, int ntlm_resp_type);
std::string make_type3_msg(std::string username, std::string password, std::string domain, std::string host, std::string msg2_b64_buff, int ntlm_resp_type);

//internal use
void calc_lmv1_resp(std::string password, const uint8_t* challenge, uint8_t* lm_resp);
void calc_ntlmv1_resp(std::string password, const uint8_t* challenge, uint8_t* ntlmv1_resp);
void calc_ntlm2session_resp(std::string password, const uint8_t* challenge, uint8_t* client_nonce, uint8_t* lm_resp, uint8_t* ntlm2session_resp);
void calc_lmv2_resp(std::string username, std::string password, std::string domain, const uint8_t* challenge, uint8_t* lmv2_resp);
void calc_ntlmv2_resp(std::string username, std::string password, std::string domain, const uint8_t* challenge, const uint8_t* target_info, uint16_t target_info_len, uint8_t* ntlmv2_resp);
void calc_ntlmv1_hash(std::string password, uint8_t* ntlmv1_hash);
void calc_ntlm2session_hash(uint8_t* session_nonce, uint8_t* session_hash);
void calc_ntlmv2_hash(std::string username, std::string password, std::string domain, uint8_t* ntlmv2_hash);
void create_client_nonce(uint8_t* nonce, size_t len);
void create_blob(const uint8_t* target_info, uint16_t target_info_len, uint8_t* blob, size_t blob_len);
void setup_security_buffer(uint16_t &temp_len,uint32_t &temp_off, uint16_t &msg_len, uint16_t &msg_max_len, uint32_t &msg_off, uint16_t len_val, uint32_t off_val);

