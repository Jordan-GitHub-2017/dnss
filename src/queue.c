struct queue {
	int tail;
	int head;
	int count;
	int size;
	u_char *element;
};

int is_empty(struct queue *qp); 
int is_full(struct queue *qp); 
int dequeue(struct queue *qp, u_char *data);
int enqueue(struct queue *qp, u_char *data); 

int enqueue(struct queue *qp, u_char *data) {
	int val = -1;

	if (!is_full(qp)) {
		strncpy((char *)(qp->element + (qp->tail*MAX_PACKET_LEN)), (char *)data, qp->size);
		
		qp->count++;
		qp->tail++;	
	
		printf("Enqueued elem: tail: %d count: %d head: %d\n\n", qp->tail, qp->count, qp->head);
		if (qp->tail == MAX_PACKET_CT) 
			qp->tail = 0;

		val = 0;	
	}else 
		printf("FULL"); 
	
	return val;
}

int dequeue(struct queue *qp, u_char *data) {
	int val = -1;


	if (!is_empty(qp)) {
		strncpy((char *)data, (char *)(qp->element + (qp->head * MAX_PACKET_LEN)), qp->size); 
		
		qp->count--;
		qp->head++;

		printf("Dequeued elem: size: %d head: %d count: %d tail: %d\n", qp->size, qp->head, qp->count, qp->head);
		if (qp->head == MAX_PACKET_CT) 
			qp->head = 0;

		val = 0;
	}else
		printf("EMPTY");

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

