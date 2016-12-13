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
void waitFor (unsigned int secs)
{
    unsigned int retTime = time(0) + secs;   // Get finishing time.
    while (time(0) < retTime);               // Loop until it arrives.
}
int main(int argc, char** argv)
{
    bool first_update = true;
    double last_update;
    double clock_time;
    char send_data[2048];

    int i,n=10,len;
    for (i=0;i<2048;i++)
      send_data[i]='\0';
    for (i=0;i<n;i++)
    {
        send_data[i] = 48+1;
    }
    send_data[i] = '\n';
    i++;
    for (;i<n+n+1;i++)
    {
        send_data[i] = 1;
    }
    printf("%s\n", send_data);
    for (i=0;i<2048;i++)
      send_data[i]='\0';
    for (i=0;i<n;i++)
    {
        send_data[i] = 48+1;
    }
    send_data[i] = '\n';
    i++;
    for (;i<n+n+1;i++)
    {
        send_data[i] = 1;
    }
    printf("%s\n", send_data);
    for (i=0;i<2048;i++)
      send_data[i]='\0';
    for (i=0;i<n;i++)
    {
        send_data[i] = 48+1;
    }
    send_data[i] = '\n';
    i++;
    for (;i<n+n+1;i++)
    {
        send_data[i] = 1;
    }
    printf("%s\n", send_data);

    return 0;
}
