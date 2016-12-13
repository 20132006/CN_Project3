/* Creates a datagram server. The port number is passed as an argument. This server runs forever */
/* tcpserver.c */

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
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>

int sock, connected;
int bytes_recieved , true_ = 1;
char send_data [1024] , recv_data[2048];
/*
 * This will handle connection for each client
 * */
void *Rhandler(void *unused)
{
    //Get the socket descriptor
    while (1)
    {
        //printf("Start receiving\n");
        bytes_recieved = recv(connected,recv_data,2048,0);

        recv_data[bytes_recieved] = '\0';

        if (strcmp(recv_data , "q") == 0 || strcmp(recv_data , "Q") == 0)
        {
            close(connected);
            break;
        }

        else
        {
            printf("----------------------------------------\n");
            printf("%s",recv_data);
            printf("----------------------------------------\n\n");
        }
        fflush(stdout);
    }
    return 0;
}

void *Shandler(void *unused)
{
    //Get the socket descriptor
    while (1)
    {
        //printf("\n SEND (q or Q to quit) : ");
        gets(send_data);

        if (strcmp(send_data , "q") == 0 || strcmp(send_data , "Q") == 0)
        {
            send(connected, send_data,strlen(send_data), 0);
            close(connected);
            break;
        }

        else
           send(connected, send_data,strlen(send_data), 0);
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char** argv)
{
    int host_port = atoi(argv[1]);
    pthread_t thread_idR;
    pthread_t thread_idS;
    struct sockaddr_in server_addr,client_addr;
    int sin_size;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket");
        exit(1);
    }

    if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&true_,sizeof(int)) == -1)
    {
        perror("Setsockopt");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(host_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_addr.sin_zero),8);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("Unable to bind");
        exit(1);
    }

    if (listen(sock, 5) == -1)
    {
        perror("Listen");
        exit(1);
    }

    printf("\nTCPServer Waiting for client on port 5000");
    fflush(stdout);


    //while(1)
    {
        sin_size = sizeof(struct sockaddr_in);
        connected = accept(sock, (struct sockaddr *)&client_addr,&sin_size);
        printf("\n I got a connection from (%s , %d)",inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));

        if( pthread_create( &thread_idR , NULL ,  Rhandler , NULL) < 0)
        {
          perror("could not create thread");
          return 1;
        }

        if( pthread_create( &thread_idS , NULL ,  Shandler , NULL) < 0)
        {
          perror("could not create thread");
          return 1;
        }

        pthread_join(thread_idS,NULL);
        pthread_join(thread_idR,NULL);
        /*
        while (1)
        {
            printf("\n SEND (q or Q to quit) : ");
            gets(send_data);

            if (strcmp(send_data , "q") == 0 || strcmp(send_data , "Q") == 0)
            {
                send(connected, send_data,strlen(send_data), 0);
                close(connected);
                break;
            }

            else
               send(connected, send_data,strlen(send_data), 0);

            fflush(stdout);
        }
        */
    }

    close(sock);
    return 0;
}
