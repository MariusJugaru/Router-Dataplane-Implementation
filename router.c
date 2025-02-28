#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPv4 0x0800
#define TTL_EXD 11
#define DST_UNRCH 3

// Routing table
struct route_table_entry *rtable;
int rtable_len;

// ARP table
struct arp_table_entry *arp_table;
int arp_table_len;

// Packets queue
queue packet_q;

void print_addr(uint8_t  ether[]) {
	for (int i = 0; i < 5; i++)
		printf("%x:", ether[i]);
	printf("%x\n", ether[5]);
}

void print_bytes(unsigned int num) {
    for (int i = 0; i < 4; i++) {
        unsigned char byte = (num >> (i * 8)) & 0xFF;
        printf("%u ", byte);
    }
	printf("\n");
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
  struct route_table_entry *best = NULL;

  for (int i = 0; i < rtable_len; i++) {
    if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {
      if (best == NULL)
        best = &rtable[i];
      else if (ntohl(best->mask) < ntohl(rtable[i].mask))
        best = &rtable[i];
    }
  }

  return best;
}

struct arp_table_entry *get_arp_entry(uint32_t ip_dest) {
  for (int i = 0; i < arp_table_len; i++) {
    if (arp_table[i].ip == ip_dest) {
      return &arp_table[i];
    }
  }

  return NULL;
}

void add_arp_entry(struct arp_header *arp_hdr)
{
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == arp_hdr->spa)
			return;
    arp_table[arp_table_len].ip = arp_hdr->spa;
    memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
    arp_table_len++;
}

int create_icmp_packet_error(char *icmp_buf, uint8_t type, struct iphdr *ip_hdr, struct ether_header *eth_hdr, int interface)
{
	// Create new packet
	memset(icmp_buf, 0, MAX_PACKET_LEN);

	// Set ether header
	struct ether_header *eth_hdr_icmp = (struct ether_header *)icmp_buf;

	memcpy(eth_hdr_icmp->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr_icmp->ether_dhost));
	memcpy(eth_hdr_icmp->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr_icmp->ether_shost));
	eth_hdr_icmp->ether_type = htons(ETHERTYPE_IPv4);

	// Set ip header
	struct iphdr *ip_hdr_icmp = (struct iphdr *)(icmp_buf + sizeof(struct ether_header));
	ip_hdr_icmp->version = 4;
	ip_hdr_icmp->ihl = 5;
	ip_hdr_icmp->id = htons(1);
	ip_hdr_icmp->protocol = 1; // ICMP
	ip_hdr_icmp->ttl = 128;

	ip_hdr_icmp->daddr = ip_hdr->saddr;
	inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr_icmp->saddr);

	// Set icmp header
	struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
			
	// Copy old ip header + first 64 bytes
	memcpy(icmp_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr) + 64);

	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 64));

	ip_hdr_icmp->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
	ip_hdr_icmp->check = htons(checksum((uint16_t *)ip_hdr_icmp, ntohs(ip_hdr_icmp->tot_len)));

	return ntohs(ip_hdr_icmp->tot_len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	char icmp_buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Code to allocate the route and arp tables
  	rtable = malloc(sizeof(struct route_table_entry) * 100000);
  	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
 	DIE(arp_table == NULL, "memory");
	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	// Router mac address
	uint8_t ether_router[6];
	get_interface_mac(0, ether_router);

	char *router_ip = get_interface_ip(0);
	printf("Router IP: %s\n", router_ip);

	

	// Allocate queue
	packet_q = queue_create();

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		printf("_________________\n");

		char *router_ip_interface = get_interface_ip(interface);
		printf("Router IP: %s\n", router_ip_interface);

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		uint8_t interface_mac[6];

		if (sizeof(*eth_hdr) < sizeof(struct ether_header)) {
			printf("Packet corrupted\n");
			memset(buf, 0, sizeof(buf));
			continue;
		}

		// Check if destination address == interface mac address || broadcast
		get_interface_mac(interface, interface_mac);
		printf("Adresa interfata: ");
		print_addr(interface_mac);

		int ok = 1;
		for (int i = 0; i < 6; i++) {
			if (interface_mac[i] != eth_hdr->ether_dhost[i] && eth_hdr->ether_dhost[i] != 0xff) {
				ok = 0;
				break;
			}
		}
		if (ok == 0) {
			printf("Wrong package\n");
			memset(buf, 0, sizeof(buf));
			continue;
		}

		printf("Adresa sursa: ");
		print_addr(eth_hdr->ether_shost);
		printf("Adresa destinatie: ");
		print_addr(eth_hdr->ether_dhost);
		printf("Adresa router: ");
		print_addr(ether_router);

		// ETHER TYPE
		uint16_t eth_type = ntohs(eth_hdr->ether_type);
		switch (eth_type) {
		case ETHERTYPE_IPv4:
			printf("IPv4\n");
			// IPv4 header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			printf("Adresa sender: ");
			print_bytes(ip_hdr->saddr);
			printf("Adresa destinatie: ");
			print_bytes(ip_hdr->daddr);

			// Check if the router is the destination
			char ip_router[20], dest[20];
			struct in_addr addr;
			
			addr.s_addr = ip_hdr->daddr;
			strcpy(dest, inet_ntoa(addr));
			strcpy(ip_router, get_interface_ip(interface));

			// printf("Dest ip\n%s\n", dest);
			// printf("Ip router\n%s\n", ip_router);
			

			if (strcmp(dest, ip_router) == 0) {
				printf("Package for router\n");

				struct icmphdr *packet_icmphdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				// Create new packet
				memset(icmp_buf, 0, MAX_PACKET_LEN);

				// Ether header
				struct ether_header *eth_hdr_icmp = (struct ether_header *)icmp_buf;
				memcpy(eth_hdr_icmp->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr_icmp->ether_dhost));
				memcpy(eth_hdr_icmp->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr_icmp->ether_shost));
				eth_hdr_icmp->ether_type = htons(ETHERTYPE_IPv4);

				// IPv4 header
				struct iphdr *ip_hdr_icmp = (struct iphdr *)(icmp_buf + sizeof(struct ether_header));
				ip_hdr_icmp->ihl = 5;
				ip_hdr_icmp->version = 4;
				ip_hdr_icmp->tos = 0;
				ip_hdr_icmp->tot_len = ip_hdr->tot_len;
				ip_hdr_icmp->frag_off = htons(0);
				ip_hdr_icmp->ttl = 128;
				ip_hdr_icmp->protocol = 1;
				ip_hdr_icmp->check = 0;
				ip_hdr_icmp->saddr = ip_hdr->daddr;
				ip_hdr_icmp->daddr = ip_hdr->saddr;

				// Icmp header
				struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				icmp_hdr->code = 0;
				icmp_hdr->type = 0;
				icmp_hdr->un.echo.id = packet_icmphdr->un.echo.id;
				icmp_hdr->un.echo.sequence = packet_icmphdr->un.echo.sequence;

				memcpy(icmp_hdr + sizeof(struct icmphdr), packet_icmphdr + sizeof(struct icmphdr), ntohs(ip_hdr_icmp->tot_len) - (sizeof(struct iphdr) + sizeof(struct icmphdr)));
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr_icmp->tot_len) - sizeof(struct iphdr)));

				ip_hdr_icmp->check = htons(checksum((uint16_t *)ip_hdr_icmp, ntohs(ip_hdr_icmp->tot_len)));

				send_to_link(interface, icmp_buf, sizeof(struct ether_header) + ntohs(ip_hdr_icmp->tot_len));
				continue;
			}

			// Checksum
			uint16_t old_sum = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t sum = checksum((uint16_t *)ip_hdr, ntohs(ip_hdr->tot_len));
			printf("New check sum: %d\n", sum);

			if (ntohs(old_sum) != sum) {
				printf("Packet corrupted\n");
				memset(buf, 0, sizeof(buf));
				continue;
			}

			// Check ttl
			if (ip_hdr->ttl <= 1) {
				printf("TTL expired\n");

				int packet_len = create_icmp_packet_error(icmp_buf, TTL_EXD, ip_hdr, eth_hdr, interface);
				
				send_to_link(interface, icmp_buf, sizeof(struct ether_header) + packet_len);
				continue;
			}

			// Update ttl and check
			uint8_t old_ttl = ip_hdr->ttl;
			ip_hdr->ttl--;
			ip_hdr->check = ~(~old_sum + ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

			// Best route
			struct route_table_entry *best_route;

			best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				printf("Route not found\n");

				int packet_len = create_icmp_packet_error(icmp_buf, DST_UNRCH, ip_hdr, eth_hdr, interface);
				
				send_to_link(interface, icmp_buf, sizeof(struct ether_header) + packet_len);
				continue;
			}

			struct arp_table_entry *nexthop_arp = get_arp_entry(best_route->next_hop);
			if (nexthop_arp == NULL) {
				printf("nu s a gasit adresa MAC\n");

				// Add packet to queue then wait for arp response
				char *packet = malloc(sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
				DIE(packet == NULL, "alloc packet");
				memcpy(packet, buf, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
				printf("Size packet: %ld\n", sizeof(*packet));
				queue_enq(packet_q, packet);

				// Ether header
				char request_buf[MAX_PACKET_LEN];
				struct ether_header *eth_request = (struct ether_header *)request_buf;

				for (int i = 0; i < 6; i++)
					eth_request->ether_dhost[i] = 0xff;
				get_interface_mac(best_route->interface, eth_request->ether_shost);
				eth_request->ether_type = htons(ETHERTYPE_ARP);

				// ARP header
				struct arp_header *arp_request = (struct arp_header *)(request_buf + sizeof(struct ether_header));

				arp_request->htype = htons(0x1);
				arp_request->ptype = htons(ETHERTYPE_IPv4);
				arp_request->hlen = 6;
				arp_request->plen = 4;
				arp_request->op = htons(0x1);

				// Set the addresses
				char ip_interface[20];

				memcpy(arp_request->sha, eth_request->ether_shost, sizeof(arp_request->sha));
				strcpy(ip_interface, get_interface_ip(best_route->interface));
				inet_pton(AF_INET, ip_interface, &arp_request->spa);
				memset(arp_request->tha, 0, sizeof(arp_request->tha));
				arp_request->tpa = best_route->next_hop;

				send_to_link(best_route->interface, request_buf, sizeof(struct ether_header) + sizeof(struct arp_header));

				continue;
			}

			memcpy(eth_hdr->ether_dhost, nexthop_arp->mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			print_addr(eth_hdr->ether_dhost);
			printf("pachet transmis pe ruta %d\n", best_route->interface);
			printf("Size %ld\n", sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));

			send_to_link(best_route->interface, buf, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));

			break;
		case ETHERTYPE_ARP:
			printf("ARP\n");
			// ARP header
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == 1) {
				// Send interface mac addr back to sender

				// Build the new ether header
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				memset(eth_hdr->ether_shost, 0, sizeof(eth_hdr->ether_shost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				// Build the new ARP header
				arp_hdr->op = htons(2);

				uint32_t interface_ip = arp_hdr->tpa;
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = interface_ip;

				memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->tha));
				memset(arp_hdr->sha, 0, sizeof(arp_hdr->sha));
				get_interface_mac(interface, arp_hdr->sha);

				send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
				continue;
			}

			printf("Adresa mac dst: ");
			print_addr(arp_hdr->tha);

			printf("Adresa mac src: ");
			print_addr(arp_hdr->sha);

            add_arp_entry(arp_hdr);
            printf("arp table len: %d\n", arp_table_len);


			// Taking packets from the queue
			// We are going to iterate through the queue, so we use a separator for the already checked packets
			char *queue_buf;

			char *queue_end = NULL;

			queue_enq(packet_q, queue_end);
			
			while ((queue_buf = queue_deq(packet_q)) != NULL) {
				struct ether_header *eth_hdr_q = (struct ether_header*)queue_buf;
				printf("Size: %ld\n", sizeof(*eth_hdr_q));
				printf("Adresa dest: ");
				print_addr(eth_hdr_q->ether_dhost);
				printf("Adresa src: ");
				print_addr(eth_hdr_q->ether_shost);

				struct iphdr *ip_hdr_q = (struct iphdr*)(queue_buf + sizeof(struct ether_header));
				printf("Size: %d\n", ntohs(ip_hdr_q->tot_len));
				printf("%p\n", ip_hdr_q);
				printf("Ip dest:");
				print_bytes(ip_hdr_q->daddr);
				printf("Ip src:");
				print_bytes(ip_hdr_q->saddr);

				// Best route
				struct route_table_entry *best_route;

				best_route = get_best_route(ip_hdr_q->daddr);
				if (best_route == NULL) {
					printf("Route not found\n");

					// TODO icmphdr
					continue;
				}

				struct arp_table_entry *nexthop_arp = get_arp_entry(best_route->next_hop);
				if (nexthop_arp == NULL) {
					// Mac addr still not available. Add the packet back to the queue
					queue_enq(packet_q, eth_hdr_q);

					continue;
				}

				memcpy(eth_hdr_q->ether_dhost, nexthop_arp->mac, sizeof(eth_hdr_q->ether_dhost));
				get_interface_mac(best_route->interface, eth_hdr_q->ether_shost);

				print_addr(eth_hdr_q->ether_dhost);
				printf("pachet transmis pe ruta %d\n", best_route->interface);
				printf("Size %ld\n", sizeof(struct ether_header) + ntohs(ip_hdr_q->tot_len));

				send_to_link(best_route->interface, queue_buf, sizeof(struct ether_header) + ntohs(ip_hdr_q->tot_len));
			}
			
			break;
		default:
			break;
		}
	}
}

