#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <net/if.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "headers.c"

int main(int argc, char **argv) {
		
	int opt;
	int redirect = 0;
	int map = 0;
	int option_ctr = 0;
	int listener_pid = 0;
	int sender_pid = 0;
	char *direction_target = (char *)calloc(SIZE_MAX_FILEN, 1);
	char *interface = (char *)calloc(SIZE_MAX_NETN, 1);
	char *target = (char *)calloc(SIZE_IP_STR, 1);
	char *redirect_target = (char *)calloc(SIZE_IP_STR, 1);
	char *map_file_name = (char *)calloc(SIZE_MAX_FILEN, 1);  
	
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

	//printf("argc: %d\nopt: %d\n", argc, option_ctr);
	
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
	
	/* fork a listener and a sender. listener always listens for dns queries
		and writes to sender process queue. sender reads count packets 
	*/
	switch (listener_pid = fork()) {
		case 0:
			return dns_listener();
			break;
		case -1:
			fprintf(stderr, "Error forking listener\n");
			exit(EXIT_FAILURE);
			break;
		default:
			switch (sender_pid = fork()) {
				case 0:
					return dns_sender();
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

	//If one child exits before the other, kill the remaining child
	wait(0);
	if (waitpid(listener_pid, 0, WNOHANG) == listener_pid) {
		fprintf(stderr, "Killing sender process and exiting\n");
		kill(listener_pid, SIGKILL);
	}

	if (waitpid(sender_pid, 0, WNOHANG) == sender_pid) {
		fprintf(stderr, "Killing listener process and exiting\n");
		kill(sender_pid, SIGKILL);
	}

	free(direction_target);
	free(interface);
	free(target);
	free(redirect_target);
	free(map_file_name);

	exit(EXIT_SUCCESS);
}

void print_usage() {
	fprintf(stderr, "dnss -i interface -t target -r|m target|file\n");
	exit(EXIT_FAILURE);
}

/* Will listen for DNS requests matching a criteria 
	and write to shared buffer */
int dns_listener(char *interface) {
	
   int sockfd;
   struct sockaddr_ll saddr;
	struct ifreq ifr;

	unsigned char *pktBuf = (unsigned char *)malloc(8192);	
	
	//Kill this child on parent's death
	prctl(PR_SET_PDEATHSIG, SIGKILL);

   if ((sockfd = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_IP)) == -1)) {
      fprintf(stderr, "Error creating listening socket\n");
      free(pktBuf);
      exit(EXIT_FAILURE);
   }

	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	if ((ioctl(sockfd, SIOCGIFINDEX, &ifr)) == -1) {
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
   while (recvfrom(sockfd, pktBuf, sizeof(pktBuf), 0, 0, 0) > 0) {
   	printf("Got data\n");
	}

	printf("listener done");
	
   free(pktBuf);
   return 0;
}

/* Reads dns packets from buffer and respond */
int dns_sender() {
	
	//Kill this child on parent's death
	prctl(PR_SET_PDEATHSIG, SIGKILL);

	return 0;
}

/* */
int build_dns() {
	return 0;
}

int send_dns() {
	return 0;
}

