#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "headers.c"

int main(int argc, char **argv) {
		
	int opt;
	int redirect = 0;
	int map = 0;
	int option_ctr = 0;
	char *direction_target = (char *)calloc(SIZE_MAX_FILEN, 1);
	char *interface = (char *)calloc(SIZE_MAX_NETN, 1);
	char *target = (char *)calloc(SIZE_IP_STR, 1);
	char *redirect_target = (char *)calloc(SIZE_IP_STR, 1);
	char *map_file_name = (char *)calloc(SIZE_MAX_FILEN, 1);  
	
	while  ((opt = getopt(argc, argv, "i:t:rm")) != -1) {
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
	
	if (option_ctr != 4 || argc != 5) {
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
		and writes to sender process queue. sender reads queuesz pac
	*/
}

void print_usage() {
	fprintf(stderr, "dnss -i interface -t target -r|m target|file");
	exit(EXIT_FAILURE);
}

/* Will listen for DNS requests matching a criteria 
	and write and 
*/
int dns_listener() {
	return 0;
}

/* Queue */
int dns_sender() {
	return 0;
}

/* */
int build_dns() {
	return 0;
}

int send_dns() {
	return 0;
}

