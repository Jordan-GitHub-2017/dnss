#define SIZE_MAX_NETN 	20
#define SIZE_IP_STR		12
#define SIZE_MAX_FILEN	60 
#define DNS_REQEST 		0
#define DNS_REPLY  		1
#define PROTO_UDP 		17
#define PORT_DNS  		53
#define MAX_PACKET_LEN	8192

#define MAX_PACKET_CT	100
#define NUM_SEM 			3
#define SEM_MUTEX 		0
#define SEM_EMPTY			1
#define SEM_FULL			2

struct eth_header {
	uint32_t dmac;
	uint16_t dmacx;
	uint32_t smac;
	uint16_t smacx;
	uint16_t type;
}__attribute__((packed));

struct ip_header{
   u_char ver;
   u_char TOS;
   uint16_t ip_len;
   uint16_t ip_id;
   uint16_t frg_offset;
   u_char TTL;
   u_char protocol;
   uint16_t chksum;
   u_char sip[4];
   u_char dip[4];
}__attribute__((packed));

struct udp_header{
	uint16_t sport;
	uint16_t dport;
	uint16_t length;
	uint16_t chksum;
}__attribute__((packed));

struct dns_header{ 
   uint16_t transID;
   uint8_t  codesFlags;
   uint16_t totalQuestions;
   uint16_t totalAnswers;
}__attribute__((packed));

