/* tcpclient.c */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include<sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h> /* for strncpy */
#include<pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

double last_update=0.0;
int first_update = 1;
char *required_filer;
int required_IP[4];
int sock;
char send_data[2048];
char recv_data[1024];

int ind;
pthread_mutex_t sendReceiveMutex;

//Linked list implementation

struct node {
   int data;

   int src1;
   int src2;
   int src3;
   int src4;

   int dst1;
   int dst2;
   int dst3;
   int dst4;

   struct node *next;
};

struct node *head = NULL;
struct node *current = NULL;

void storeData(int num)
{
    int k=0;
    char temp[30];
    while (num>0)
    {
        temp[++k] = num%10;
        num/=10;
    }
    --k;
    for (;k>=0;k--)
    {
        send_data[++ind] = temp[k];
    }
}

//display the list
void sendList() {

    ind = 0;
    struct node *ptr = head;

    memset(send_data, 0, sizeof (send_data));;
    //start from the beginning
    while(ptr != NULL)
    {
        if (strcmp(required_filer , "filter:all") == 0)
        {
            storeData(ptr->src1);send_data[++ind] = '.';
            storeData(ptr->src2);send_data[++ind] = '.';
            storeData(ptr->src3);send_data[++ind] = '.';
            storeData(ptr->src4);send_data[++ind] = '-';send_data[++ind] = '>';
            storeData(ptr->dst1);send_data[++ind] = '.';
            storeData(ptr->dst2);send_data[++ind] = '.';
            storeData(ptr->dst3);send_data[++ind] = '.';
            storeData(ptr->dst4);send_data[++ind] = ':';
            storeData(ptr->data);send_data[++ind] = '\n';
        }
        else if (strcmp(required_filer , "filter:star") == 0 &&
        (ptr->src1 == required_IP[0] && ptr->src3 == required_IP[1] && ptr->src3 == required_IP[2]) ||
        (ptr->dst1 == required_IP[0] && ptr->dst2 == required_IP[1] && ptr->dst3 == required_IP[2]) )
        {
            storeData(ptr->src1);send_data[++ind] = '.';
            storeData(ptr->src2);send_data[++ind] = '.';
            storeData(ptr->src3);send_data[++ind] = '.';
            storeData(ptr->src4);send_data[++ind] = '-';send_data[++ind] = '>';
            storeData(ptr->dst1);send_data[++ind] = '.';
            storeData(ptr->dst2);send_data[++ind] = '.';
            storeData(ptr->dst3);send_data[++ind] = '.';
            storeData(ptr->dst4);send_data[++ind] = ':';
            storeData(ptr->data);send_data[++ind] = '\n';
        }
        else if (strcmp(required_filer , "filter:full") == 0 &&
        (ptr->src1 == required_IP[0] && ptr->src3 == required_IP[1] &&
          ptr->src3 == required_IP[2] && ptr->src4 == required_IP[3]) ||
        (ptr->dst1 == required_IP[0] && ptr->dst2 == required_IP[1] &&
          ptr->dst3 == required_IP[2] && ptr->dst4 == required_IP[3]) )
        {
            storeData(ptr->src1);send_data[++ind] = '.';
            storeData(ptr->src2);send_data[++ind] = '.';
            storeData(ptr->src3);send_data[++ind] = '.';
            storeData(ptr->src4);send_data[++ind] = '-';send_data[++ind] = '>';
            storeData(ptr->dst1);send_data[++ind] = '.';
            storeData(ptr->dst2);send_data[++ind] = '.';
            storeData(ptr->dst3);send_data[++ind] = '.';
            storeData(ptr->dst4);send_data[++ind] = ':';
            storeData(ptr->data);send_data[++ind] = '\n';
        }
        printf("(%d.%d.%d.%d) ->",ptr->src1,ptr->src2,ptr->src3,ptr->src4);
        printf("(%d.%d.%d.%d) : %d\n",ptr->dst1,ptr->dst2,ptr->dst3,ptr->dst4,ptr->data);
        ptr = ptr->next;
    }
    send(sock,send_data,strlen(send_data), 0);

}

//insert link at the first location
void insertFirst(int src1, int src2, int src3, int src4,
                 int dst1, int dst2, int dst3, int dst4, int data) {
   //create a link
   struct node *link = (struct node*) malloc(sizeof(struct node));

   link->src1 = src1;
   link->src2 = src2;
   link->src3 = src3;
   link->src4 = src4;

   link->dst1 = dst1;
   link->dst2 = dst2;
   link->dst3 = dst3;
   link->dst4 = dst4;

   link->data = data;

   //point it to old first node
   link->next = head;

   //point first to new first node
   head = link;
}

//delete first item
struct node* deleteFirst() {

   //save reference to first link
   struct node *tempLink = head;

   //mark next to first link as first
   head = head->next;

   //return the deleted link
   return tempLink;
}

//is list empty
bool isEmpty() {
   return head == NULL;
}

int length() {
   int length = 0;
   struct node *current;

   for(current = head; current != NULL; current = current->next) {
      length++;
   }

   return length;
}

//find a link with given key
struct node* find(int src1, int src2, int src3, int src4,
                    int dst1, int dst2, int dst3, int dst4) {

   //start from the first link
   struct node* current = head;

   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while(current->src1 != src1 && current->src2 != src2 && current->src3 != src3 && current->src4 != src4
      && current->dst1 != dst1 && current->dst2 != dst2 && current->dst3 != dst3 && current->dst4 != dst4) {

      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //go to next link
         current = current->next;
      }
   }

   //if data found, return the current Link
   return current;
}


//delete a link with given key
struct node* delete(int src1, int src2, int src3, int src4,
                    int dst1, int dst2, int dst3, int dst4) {

   //start from the first link
   struct node* current = head;
   struct node* previous = NULL;

   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while(current->src1 != src1 && current->src2 != src2 && current->src3 != src3 && current->src4 != src4
      && current->dst1 != dst1 && current->dst2 != dst2 && current->dst3 != dst3 && current->dst4 != dst4) {

      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //store reference to current link
         previous = current;
         //move to next link
         current = current->next;
      }
   }

   //found a match, update the link
   if(current == head) {
      //change first to point to next link
      head = head->next;
   } else {
      //bypass the current link
      previous->next = current->next;
   }

   return current;
}



















#define SNAP_LEN 1518

struct arg_struct{
    //passing argument struct
    int numberOfPackets;
    char *filtering_rule;
    char *hostIP;
    int Sport;
};

//Callback function is called when the packet passes through the filter.
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt =0;
    int length=pkthdr->len;

    //Get the ethernet header.
    ep = (struct ether_header *)packet;
    //In order to get IP header, offset a size of ethernet header.
    packet += sizeof(struct ether_header);
    //Get a protocol type.
    ether_type = ntohs(ep->ether_type);

    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    struct ip *iph = (struct ip *)packet;
    char *src;
    src = (char *)malloc(40*sizeof(char));
    //memseit(src, '\0',sizeof(src));
    strcpy(src,inet_ntoa(iph->ip_src));
    //printf("%s\n",src);
    char *dest;
    dest = (char *)malloc(40*sizeof(char));
    //memseit(src, '\0',sizeof(src));
    strcpy(dest,inet_ntoa(iph->ip_dst));
    //printf("%s\n",src);
    char *ipaddr;
    ipaddr = (char *)malloc(40*sizeof(char));
    strcpy(ipaddr,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    int res = strcmp(ipaddr,src);
    //printf("%d\n", res);
    int res1 = strcmp(ipaddr,dest);
    //printf("%d\n", res);

    int i;
    int len;
    int src1[4];
    int src2[4];
    int k=0;
    len = strlen(src);
    src1[0]=src1[1]=src1[2]=src1[3]=0;
    for (i=0;i<len;++i)
    {
        if (src[i] == '.')
        {
            k++;
        }
        else
        {
            src1[k] = (src1[k] * 10) + (src[i]-48);
        }
    }

    k=0;
    len = strlen(dest);
    src2[0]=src2[1]=src2[2]=src2[3]=0;
    for (i=0;i<len;++i)
    {
        if (dest[i] == '.')
        {
            k++;
        }
        else
        {
            src2[k] = (src2[k] * 10) + (dest[i]-48);
        }
    }
    pthread_mutex_lock(&sendReceiveMutex);/*                                  lock and check requred_filer*/
    double clock_time = clock();
    if (first_update)
    {
        last_update = clock_time;
        first_update = 0;
    }
    else if (!first_update)
    {
        double time_spent = (double)(clock_time - last_update);
        printf("%f\n", time_spent);
        if (time_spent >= 60000000)
        {
            sendList();
            while (!isEmpty())
            {
                deleteFirst();
            }
            last_update = clock_time;
        }

    }
    struct node *temp;
    temp = find(src1[0],src1[1],src1[2],src1[3],src2[0],src2[1],src2[2],src2[3]);
    if (temp != NULL)
    {
        printf("temp not NULL we are just increasing data\n");
        temp->data++;
    }
    else
    {
        printf("temp is NULL and we are adding data\n");
        insertFirst(src1[0],src1[1],src1[2],src1[3],src2[0],src2[1],src2[2],src2[3],0);
    }
    pthread_mutex_unlock(&sendReceiveMutex);/*                                  unlock and check requred_filer*/
    if (!res || !res1)
    {
        printf("Version     : %u\n", iph->ip_v );
        printf("Header Len  : %u\n", iph->ip_hl);
        printf("Ident       : %d\n", iph->ip_id);
        printf("TTL         : %u\n", iph->ip_ttl);
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
    	  printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));
        printf("\n\n");
    }
}







int num_packets;			/* number of packets to capture */
char *filter_exp;		/* filter expression [3] */

void *pcap(void *unused)
{
    //struct arg_struct *argum;
    //argum  = (struct arg_struct *) arguments;

    char *dev = NULL;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;
    struct bpf_program fp;

    pcap_t *pcd;
  //added by Alibek

    pcap_t *handle;				/* packet capture handle */


    //Get a current device name.
    dev = pcap_lookupdev(errbuf);
    //printf("Stoped here %s\n", dev);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        printf("Couldn't get netmask for device %s: %s\n",dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        exit(1);
    }
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        printf("%s is not an Ethernet\n", dev);
        exit(1);
    }
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
        exit(1);
    }
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
        exit(1);
    }
    /* now we can set our callback function */
    pcap_loop(handle, num_packets, callback, NULL);
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("\nCapture complete.\n");
    return 0;
}







void get_requirements()
{
    int len = strlen(recv_data);
    int i=0;
    while (recv_data[i]!=':')
    {
        i++;
    }
    i++;
    int k;
    for (k=0;k<3;++k)
    {
        required_IP[k]=0;
        while (recv_data[i]!='.')
        {
            required_IP[k] = required_IP[k]*10 + (recv_data[i]-48);
            ++i;
        }
    }
    ++i;
    if (recv_data[i]=='*')
    {
        strcpy(required_filer,"filter:star");
    }
    else
    {
        strcpy(required_filer,"filter:full");
        required_IP[k]=0;
        while (i<len)
        {
            required_IP[k] = required_IP[k]*10 + (recv_data[i]-48);
            ++i;
        }
    }
}

void *connection_handler(void *unused)
{
    int bytes_recieved;

    while(1)
    {

        bytes_recieved=recv(sock,recv_data,1024,0);
        recv_data[bytes_recieved] = '\0';

        printf("Bytes Received : %d", bytes_recieved);
        printf("Data Received : %s", recv_data);

        if (strcmp(recv_data , "q") == 0 || strcmp(recv_data , "Q") == 0)
        {
            close(sock);
            break;
        }
        else if (bytes_recieved != 0)
        {
            pthread_mutex_lock(&sendReceiveMutex);/*                                  lock and check requred_filer*/
            get_requirements();
            pthread_mutex_unlock(&sendReceiveMutex);/*                                  lock and check requred_filer*/
            printf("\nRecieved data = %s " , recv_data);
        }
        /*
        printf("\nSEND (q or Q to quit) : ");
        gets(send_data);

        if (strcmp(send_data , "q") != 0 && strcmp(send_data , "Q") != 0)
            send(sock,send_data,strlen(send_data), 0);

        else
        {
            send(sock,send_data,strlen(send_data), 0);
            close(sock);
            break;
        }
        */
    }
}

int main(int argc, char** argv)
{
    num_packets = atoi(argv[1]);			/* number of packets to capture */
    filter_exp = argv[2];		/* filter expression [3] */

    int bytes_recieved;
    char recv_data[1024];
    struct hostent *host;
    char *host_name = argv[3];
    int host_port = atoi(argv[4]);
    struct sockaddr_in server_addr;
    pthread_t idPcapThread;
    pthread_t idConnectionThread;

    host = gethostbyname(host_name/*"127.0.0.1"*/);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("Socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(host_port);
    server_addr.sin_addr = *((struct in_addr *)host->h_addr);
    bzero(&(server_addr.sin_zero),8);



    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("Connect");
        exit(1);
    }

    required_filer = (char *)malloc(40*sizeof(char));
    //memseit(src, '\0',sizeof(src));
    strcpy(required_filer,"filter:all");

    if (pthread_mutex_init(&sendReceiveMutex, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }


    if( pthread_create( &idPcapThread , NULL ,  pcap , NULL) < 0)
    {
        perror("could not create thread");
        return 1;
    }
    if( pthread_create( &idConnectionThread , NULL ,  connection_handler , NULL) < 0)
    {
        perror("could not create thread");
        return 1;
    }


    pthread_join(idPcapThread, NULL);
    pthread_join(idConnectionThread, NULL);

    /*
    while(1)
    {
        bytes_recieved=recv(sock,recv_data,1024,0);
        recv_data[bytes_recieved] = '\0';

        if (strcmp(recv_data , "q") == 0 || strcmp(recv_data , "Q") == 0)
        {
            close(sock);
            break;
        }

        else
            printf("\nRecieved data = %s " , recv_data);

        printf("\nSEND (q or Q to quit) : ");
        gets(send_data);

        if (strcmp(send_data , "q") != 0 && strcmp(send_data , "Q") != 0)
            send(sock,send_data,strlen(send_data), 0);

        else
        {
            send(sock,send_data,strlen(send_data), 0);
            close(sock);
            break;
        }
    }
    */
    //pthread_join();
    return 0;
}
