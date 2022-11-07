#define ETH_LEN	1518
#define ETHER_TYPE	0x0808
#define DEFAULT_IF	"eth0"
#define IP_BROADCAST "255.255.255.255"
#define IP_DEST_PLACEHOLDER "192.168.1.123"
#define PROTO_UDP	17
#define DHCP_PORT	67
#define DHCP_PORT_2	68
#define DHCP_DISCOVER_NAME "DHCPDISCOVER"
#define DHCP_REQUEST_NAME "DHCPREQUEST"

struct eth_hdr_s {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct ip_hdr_s {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	uint16_t len;			/* total length */
	uint16_t id;			/* identification */
	uint16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct udp_hdr_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udp_len;
	uint16_t udp_chksum;
};

struct dhcp_message {
	uint8_t op_code;			/* Operation code */
	uint8_t htype;				/* Hardware type */
	uint8_t hlen;				/* Hardware address length */
	uint8_t hops;				/* Hops */
	uint32_t xid;				/* Transaction ID */
	uint16_t sec;				/* Seconds */
	uint16_t flags;				/* Flags */
	uint8_t ciaddr[4];			/* Client IP address */
	uint8_t yiaddr[4];			/* Your IP address */
	uint8_t siaddr[4];			/* Server IP address */
	uint8_t giaddr[4];			/* Gateway IP address */
	uint8_t chaddr[16];			/* Client hardware address */
    uint8_t sname[64]; 			/* Server host name */
    uint8_t file[128];  		/* Boot file name */
    uint8_t options[312]; 		/* Optional parameters field */
};

struct eth_frame_s {
	struct eth_hdr_s ethernet;
	struct ip_hdr_s ip;
	struct udp_hdr_s udp;
};

