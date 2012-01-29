struct queue {
	int tail;
	int head;
	int count;
	int size;
	u_char **element;
};

int is_empty(struct queue *qp); 
int is_full(struct queue *qp); 
int dequeue(struct queue *qp, u_char *data);
int enqueue(struct queue *qp, u_char *data); 

int enqueue(struct queue *qp, u_char *data) {
	int val = 0;

	printf("Enqueuing elem: tail: %d count: %d head: %d\n\n", qp->tail, qp->count, qp->head);

	if (!is_full(qp)) {
		strncpy((char *)(qp->element[qp->tail++]), (char *)data, qp->size);
		qp->count++;
	
		if (qp->tail == MAX_PACKET_CT) 
			qp->tail = 0;
		
		val = 1;
		printf("VAL SET TO ZERO ENQUEUE");
	} 
	
	return val;
}

int dequeue(struct queue *qp, u_char *data) {
	int val = 0;

	printf("Dequeuing elem: head: %d count: %d tail: %d\n", qp->head, qp->count, qp->head);

	if (!is_empty(qp)) {
		strncpy((char *)data, (char *)qp->element[qp->head++], qp->size); 
		qp->count--;

		if (qp->head == MAX_PACKET_CT) 
			qp->tail = 0;

		val = 1;
	}
	return val;
}

int is_full(struct queue *qp) {
	if (qp->count == MAX_PACKET_CT) 
		return 1;
	return 0;
}

int is_empty(struct queue *qp) {
	if (qp->count == 0) 
		return 1;
	return 0;
}

