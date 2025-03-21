#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include <signal.h>

typedef struct {
    struct pcap_pkthdr header;
    u_char *data; 
} Packet;

typedef struct Node {
    Packet packet;
    struct Node *next;
} Node;

typedef struct {
    Node *front;
    Node *rear;
} Queue;

Queue queue;
volatile sig_atomic_t stop_capture = 0; 

void handle_signal(int signum) {
    stop_capture = 1; 
}

void init_queue() {
    queue.front = NULL;
    queue.rear = NULL;
}

int empty() {
    return queue.front == NULL;
}

void enqueue(const struct pcap_pkthdr *header, const u_char *data) {
    Node *newNode = (Node *)malloc(sizeof(Node));
    if (newNode == NULL) {
        perror("malloc");
        return;
    }
    newNode->packet.header = *header;
    newNode->packet.data = (u_char *)malloc(header->len);
    if (newNode->packet.data == NULL) {
        perror("malloc");
        free(newNode);
        return;
    }
    memcpy(newNode->packet.data, data, header->len); 
    newNode->next = NULL;

    if (empty()) {
        queue.front = newNode;
    } else {
        queue.rear->next = newNode;
    }
    queue.rear = newNode;
}

Packet* dequeue() {
    if (empty()) {
        return NULL; 
    }

    Node *temp = queue.front;
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    if(packet == NULL){
        perror("malloc");
        return NULL;
    }
    *packet = temp->packet; 
    queue.front = queue.front->next;

    if (queue.front == NULL) {
        queue.rear = NULL;
    }

    free(temp);
    return packet;
}

void free_packet(Packet *packet) {
    if (packet != NULL) {
        free(packet->data);
        free(packet);
    }
}

void free_queue() {
    while (!empty()) {
        Node *temp = queue.front;
        queue.front = queue.front->next;
        free(temp->packet.data);
        free(temp);
    }
    queue.rear = NULL;
}

void start_capture(char* interface, char* filter, int timeout,int total_packages, int total_length) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    time_t start_time, current_time;
    struct pcap_pkthdr *header;
    const u_char *data;
    int packet_count = 0;
    int total_bytes = 0;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    init_queue();
    handle = pcap_open_live(interface, 65536, 1, -1, errbuf);

    if (bpf_filter != NULL) {
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "No se pudo compilar el filtro BPF: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "No se pudo aplicar el filtro BPF: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        pcap_freecode(&fp);
    }
    
    time(&start_time);
    while (!stop_capture) {
        time(&current_time);
        if (timeout > 0 && difftime(current_time, start_time) >= timeout) {
            break;
        }
        if(1==pcap_next_ex(handle,&header,&data)){
            packet_count++;
            total_bytes += header->len;
            enqueue(header,data);
                
            if (total_packages > 0 && packet_count >= total_packages) {
                break;
            }
            if (total_length > 0 && total_bytes >= total_length) {
                break;
            }
        }
    }
}
