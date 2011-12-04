#define SIZE_MAX_NETN 20
#define SIZE_IP_STR		12
#define SIZE_MAX_FILEN	60 
#define DNS_REQEST 0
#define DNS_REPLY  1
#define MAX_DNS_

struct dns_header{ 
   uint16_t transID;
   uint8_t  codesFlags;
   uint16_t totalQuestions;
   uint16_t totalAnswers;
}; 

int dns_sender(); 
int dns_listener();
int send_dns();
int build_dns(); 
void print_usage();

