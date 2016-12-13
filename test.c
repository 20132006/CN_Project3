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

    while (1)
    {
        clock_time = clock();
        if (first_update)
        {
            last_update = clock_time;
            first_update = false;
            printf("%f\n", clock_time);
        }
        else if (!first_update && clock_time - last_update >= 60000000)
        {
            printf("%f\n", clock_time);
            last_update = clock_time;
        }
    }
    return 0;
}
