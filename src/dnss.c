#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <features.h>
#include <errno.h>

#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <semaphore.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "headers.c"
#include "queue.c"
#include "dnss_defs.c"

int main(int argc, char **argv) {
		
	int opt;
	int redirect = 0;
	int map = 0;
	int option_ctr = 0;
	int listener_pid = 0;
	int sender_pid = 0;
	int smem_id = 0;
	key_t smem_key = 0;	
	sem_t *semaphores[3];

	char *direction_target = (char *)calloc(SIZE_MAX_FILEN, 1);
	char *interface = (char *)calloc(IFNAMSIZ, 2);
	char *target = (char *)calloc(SIZE_IP_STR, 1);
	char *redirect_target = (char *)calloc(SIZE_IP_STR, 1);
	char *map_file_name = (char *)calloc(SIZE_MAX_FILEN, 1);  
	
	if (geteuid() != 0) {
		fprintf(stderr, "dnss requires root permissions!\n");
		exit(EXIT_FAILURE);
	}
	
	if ((smem_key = ftok(SMEM_KEY, SMEM_KEYID)) == -1) {
		perror("ftok");
		exit(EXIT_FAILURE);
	} 	
	
	if ((smem_id = shmget(smem_key, MAX_PACKET_LEN * MAX_PACKET_CT + sizeof(struct queue), IPC_CREAT | 0666)) < 0) {
		perror("shmget");
		exit(EXIT_FAILURE);
	} 	

	while ((opt = getopt(argc, argv, "i:t:rm")) != -1) {
		switch (opt) {
			case 'i':
				strncpy(interface, optarg, SIZE_MAX_NETN);
				break;
			case 't':
				strncpy(target, optarg, SIZE_IP_STR);
				break;
			case 'r':
				if (map == 1) {
					print_usage();
				}
				redirect = 1;
				break;
			case 'm':
				if (redirect == 1) {	
					print_usage();	
				}
				map = 1;
				break;
		}
		option_ctr++;
	}
	
	if (option_ctr != 3 || argc != 7) {
		print_usage();
	}
		
	if (optind < argc) {	
		if (redirect) { 
			strncpy(direction_target, argv[optind], SIZE_IP_STR);		
		}else if (map) {
			strncpy(direction_target, argv[optind], SIZE_MAX_FILEN);
		}
	}
	
   if (init_semaphores(semaphores) == -1) 
		exit(EXIT_FAILURE);

	/* fork a listener and a sender. listener always listens for dns queries
		and writes to sender process queue. sender reads count packets	*/
	switch (listener_pid = fork()) {
		case 0:
			return dns_listener(interface, target, semaphores, smem_id);
			break;
		case -1:
			fprintf(stderr, "Error forking listener\n");
			exit(EXIT_FAILURE);
			break;
		default:
			switch (sender_pid = fork()) {
				case 0:
					return dns_sender(interface, semaphores, smem_id, target);
					break;
				case -1:
					fprintf(stderr, "Error forking sender\n");
					exit(EXIT_FAILURE);			
					break;
				default:
				break;
			}
			break;
	}
	
	//Make sure children have time to install PDEATHSIG handler
	sleep(1);

	//If one child exits before the other, kill the remaining child
	waitpid(-1, 0, 0);
	if (waitpid(listener_pid, 0, WNOHANG) == 0) {
		fprintf(stderr, "Killing sender process and exiting\n");
		kill(listener_pid, SIGKILL);
	}

	if (waitpid(sender_pid, 0, WNOHANG) == 0) {
		fprintf(stderr, "Killing listener process and exiting\n");
		kill(sender_pid, SIGKILL);
	}

	sem_close(semaphores[SEM_MUTEX]);
	sem_close(semaphores[SEM_EMPTY]);
	sem_close(semaphores[SEM_FULL]);

	//free_packet_buffer((char **)qp->element);

	free(direction_target);
	free(interface);
	free(target);
	free(redirect_target);
	free(map_file_name);

	exit(EXIT_SUCCESS);
}

int free_packet_buffer(char **pkt_buf) {
	int i;
	
	for (i = 0; i < MAX_PACKET_CT; i++) {
		free(pkt_buf[i]);
	}

	free(pkt_buf);
	return 0;
}

int init_semaphores(sem_t **semaphores) {
	if ((semaphores[SEM_MUTEX] = sem_open("lock1", O_CREAT, 0644, 1)) == SEM_FAILED) {
		perror("Semaphore full initialization");
		return -1;
	}
	
	if ((semaphores[SEM_EMPTY] = sem_open("lock2", O_CREAT, 0644, MAX_PACKET_CT)) == SEM_FAILED) {
		perror("Semaphore full initialization");
		return -1;

	} 

	if ((semaphores[SEM_FULL] = sem_open("lock3", O_CREAT, 0644, 0)) == SEM_FAILED) {
		perror("Semaphore full initialization");
		return -1;
	}
	
	return 0;
}

void print_usage() {
	fprintf(stderr, "dnss -i interface -t target -r|m target|file\n");
	exit(EXIT_FAILURE);
}

void sigproc(int signo) {
	exit(EXIT_FAILURE);
}

char *get_smem_ptr(int shmid) {
   char *shm; 

	if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
        perror("shmat");
        exit(1);
    }
	 return shm;
}

void init_queue(char *smem_ptr) {
	struct queue *qp;
	qp = (struct queue *)smem_ptr;
	
	qp->tail = 0;
	qp->head = 0;
	qp->count = 0;
	qp->size = 8192;
	qp->element = (u_char *)smem_ptr + sizeof(struct queue);
}

/* Will listen for DNS requests matching a criteria 
	and write to shared buffer */
int dns_listener(char *interface, char *target_ip, sem_t **semaphores, int smem_id) {
	
   int sockfd;
   struct sockaddr_ll saddr;
	struct ifreq ifr;
	struct ip_header *ip;
	struct udp_header *udp;
	char *smem_ptr;
	struct queue *queue;

	unsigned char *pktBuf = (unsigned char *)calloc(MAX_PACKET_LEN+5, 1);	
	
	//signal(SIGHUP, sigproc);	

	bzero(&saddr, sizeof(saddr));
	bzero(&ifr, sizeof(ifr));

	if (prctl(PR_SET_PDEATHSIG, SIGHUP) != 0) {
		fprintf(stderr, "Unable to install parent death sig\n");
	}

	smem_ptr = get_smem_ptr(smem_id); 
	init_queue(smem_ptr);
	queue = (struct queue *)smem_ptr;

   if ((sockfd = socket (PF_PACKET, SOCK_RAW, 0)) == -1) {
      perror("Error creating listening socket\n");
      free(pktBuf);
      exit(EXIT_FAILURE);
   }

	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	if ((ioctl(sockfd, SIOCGIFINDEX, &ifr)) < 0) {
		fprintf(stderr, "Unable to get interface index!\n");
		exit(EXIT_FAILURE);
	} 

	//Bind the socket to the specified interface
	saddr.sll_family = AF_PACKET;
	saddr.sll_ifindex = ifr.ifr_ifindex;
	saddr.sll_protocol = htons(ETH_P_IP);

	if ((bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr))) == -1) {
		perror("Error binding raw socket to interface\n");
		exit(EXIT_FAILURE);
	}
	
	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	
	while (recvfrom(sockfd, pktBuf, 8192, 0, 0, 0) > 0) {
		int ip_len;

		ip = (struct ip_header *)(pktBuf + sizeof(struct eth_header));
		ip_len = 4 * ((ip->ver) & 0x0f);		
		
		//Change to dport when done testing in switched environment
      if (ip->protocol == (char)PROTO_UDP && !compare_ip(target_ip, ip->sip)) {
		   udp = (struct udp_header *)(pktBuf + sizeof(struct eth_header) + ip_len);
			if (htons(udp->sport) == PORT_DNS) {
			   printf("UDP sport: %hu, dport: %hu\n", ntohs(udp->sport), ntohs(udp->dport));
				
				sem_wait(semaphores[SEM_EMPTY]);
				sem_wait(semaphores[SEM_MUTEX]);			

				enqueue(queue, pktBuf);				

				sem_post(semaphores[SEM_MUTEX]);
				sem_post(semaphores[SEM_FULL]);			
			}
		}
	}

	printf("listener done");
	
   free(pktBuf);
	close(sockfd);
   return 0;
}

int compare_ip(char *target, u_char *cur_ip) {
	int i;
	char *cur_ip_str = (char *)calloc(SIZE_IP_STR, 2);
	char *tmp = (char *)calloc(SIZE_IP_STR, 2);
	return 0;

	for (i=0; i<4; i++) {
		sprintf(tmp, "%d", cur_ip[i]);
		strncat(cur_ip_str, tmp, SIZE_IP_STR);
		if (i != 3) 
			strcat(cur_ip_str, ".");
		memset(tmp, 0, SIZE_IP_STR);
	}
	
	i = strncmp(cur_ip_str, target, strlen(target));
	free(cur_ip_str);	
	free(tmp);
	return i;
}

/* Reads dns packets from buffer and respond */
int dns_sender(char *interface, sem_t **semaphores, int smem_id, char *targer) {
	/*protocol headers*/
	struct dns_header *dns; 
	/*shared mem*/
	char *smem_ptr = smem_ptr = get_smem_ptr(smem_id); 
	/*socket vars*/
	int sockfd;
	struct ifreq ifr;
	/*packet buffers*/
	u_char *queue_item = (u_char *)calloc(MAX_PACKET_LEN+5, 1);
	u_char *response = (u_char *)calloc(MAX_PACKET_LEN, 1);

   if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("Sender socket failed.");
      exit(EXIT_FAILURE);
   }

   /* Set our ifr struct family to IPV4 */
   ifr.ifr_addr.sa_family = AF_INET;
   /* Copy interface name to ifr_name */
   strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

   /* IOCTL:
      SIOGIFADDR gets an interface addr
      SIOCSIFADDR sets an interface addr
      SIOCGHWADDR gets locak HW addr
    */
   if (ioctl(sockfd, SIOCGIFHWADDR, (char *)&ifr) < 0) {
      perror("ioctl");
      exit(EXIT_SUCCESS);
   }

   /* Set our ifr struct family to IPV4 */
	//signal(SIGHUP, sigproc);	
	prctl(PR_SET_PDEATHSIG, SIGHUP);
	
	while(1) {
		sem_wait(semaphores[SEM_FULL]);
		sem_wait(semaphores[SEM_MUTEX]);

		dequeue((struct queue *)smem_ptr, queue_item);
		
		sem_post(semaphores[SEM_MUTEX]);
		sem_post(semaphores[SEM_EMPTY]);
		
		dns = (struct dns_header *)get_dns_ptr((u_char *)queue_item);
		build_dns(queue_item, response);
	}

	return 0;
}

u_char *get_dns_ptr(u_char *pkt_buf) {
		int ip_len;
		struct ip_header *ip;
		struct udp_header *udp;

		ip = (struct ip_header *)(pkt_buf + sizeof(struct eth_header));
		ip_len = 4 * ((ip->ver) & 0x0f);		
		
		udp = (struct udp_header *)(pkt_buf + sizeof(struct eth_header) + ip_len);
				
		return (u_char *)(udp+sizeof(struct udp_header));
}

void print_buf(u_char *pkt) {
	int i = 0;
	
	for (i = 0; i < 100; i++) {
		printf("%x ", pkt[i]);	
	}
	printf("\n");
}

void build_dns(u_char *queue_item, u_char *response) {
	struct eth_header *eth;
	struct ip_header *ip;
	struct udp_header *udp;
	struct dns_header *dns;


	eth = (struct eth_header *)response;
	ip = (struct ip_header *)(response + sizeof(struct eth_header));
}



int send_dns() {
	return 0;
}

