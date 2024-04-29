#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "lib/tdns/tdns-c.h"

/* DNS header structure */
struct dnsheader {
        uint16_t        id;         /* query identification number */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritative answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        rcode :4;       /* response code */
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ 
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritative answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        uint16_t        qdcount;    /* number of question records */
        uint16_t        ancount;    /* number of answer records */
        uint16_t        nscount;    /* number of authority records */
        uint16_t        arcount;    /* number of resource records */
};

/* A few macros that might be useful */
/* Feel free to add macros you want */
#define DNS_PORT 53
#define BUFFER_SIZE 2048 

int main() {
    /* A few variable declarations that might be useful */
    /* You can add anything you want */
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    struct TDNSServerContext* context;
    /* PART2 TODO: Implement a local iterative DNS server */
    
    /* 1. Create an **UDP** socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    /* 2. Initialize server address (INADDR_ANY, DNS_PORT) */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    /* Then bind the socket to it */
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    /* 3. Initialize a server context using TDNSInit() */
    /* This context will be used for future TDNS library function calls */
    context = TDNSInit();

    /* 4. Create the edu zone using TDNSCreateZone() */
    /* Add the UT nameserver ns.utexas.edu using using TDNSAddRecord() */
    /* Add an IP address for ns.utexas.edu domain using TDNSAddRecord() */
    TDNSCreateZone(context, "edu");
    TDNSAddRecord(context, "edu", NULL, NULL, "ns.utexas.edu");  // Delegate to ns.cs.utexas.edu
    TDNSAddRecord(context, "edu", "ns.utexas", "40.0.0.20", NULL);  // ns.utexas.edu NS IP address

    /* 5. Receive a message continuously and parse it using TDNSParseMsg() */
    while (1) {
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                    (struct sockaddr *)&client_addr, &client_len);
        if (recv_len > 0) {
            struct TDNSParseResult parsed;
            uint8_t query_or_response = TDNSParseMsg(buffer, recv_len, &parsed);
            if (query_or_response == TDNS_QUERY) {

                /* 6. If it is a query for A, AAAA, NS DNS record, find the queried record using TDNSFind() */
                /* You can ignore the other types of queries */
                if (parsed.qtype == A || parsed.qtype == AAAA || parsed.qtype == NS) {
                    struct TDNSFindResult result;
                    uint8_t found_record = TDNSFind(context, &parsed, &result);
                    bool do_delegation = (parsed.nsDomain != NULL) ? true : false;

                    /* a. If the record is found and the record indicates delegation, */
                    /* send an iterative query to the corresponding nameserver */
                    /* You should store a per-query context using putAddrQID() and putNSQID() */
                    /* for future response handling */
                    if (found_record && do_delegation) {
                        // IP address of the nameserver and domain(?) of the nameserver
                        const char* nameserverIP = parsed.nsIP;
                        const char* nameserverDomain = parsed.nsDomain;

                        // Basically, the idea here is to just get the address to relay our received message to
                        struct sockaddr_in new_addr;
                        memset(&new_addr, 0, sizeof(new_addr));
                        new_addr.sin_family = AF_INET;
                        inet_pton(AF_INET, nameserverIP, new_addr.sin_addr.s_addr)
                        new_addr.sin_port = htons(DNS_PORT);

                        socklen_t new_addr_len = sizeof(new_addr);

                        ssize_t send_len = sendto(sockfd, buffer, recv_len, 0,
                                                  (struct sockaddr *)&new_addr, new_addr_len);
                        if (send_len < 0) {
                            perror("Sendto failed");
                        }
                        putAddrQID(context, parsed.dh->id, &client_addr);
                        putNSQID(context, parsed.dh->id, nameserverIP, nameserverDomain);
                    }
                    /* b. If the record is found and the record doesn't indicate delegation, send a response back*/
                    /* c. If the record is not found, send a response back */
                    else if (!found_record || (found_record && !do_delegation)) {
                        // Send the response
                        ssize_t send_len = sendto(sockfd, result.serialized, result.len, 0,
                                                  (struct sockaddr *)&client_addr, client_len);
                        if (send_len < 0) {
                            perror("Sendto failed");
                        }
                    }
                    else {
                        // ERROR: SHOULD NEVER REACH THIS
                    }
                }
            }
            else if (query_or_response == TDNS_RESPONSE) {
                /* 7. If the message is an authoritative response (i.e., it contains an answer), */
                /* add the NS information to the response and send it to the original client */
                /* You can retrieve the NS and client address information for the response using */
                /* getNSbyQID() and getAddrbyQID() */
                /* You can add the NS information to the response using TDNSPutNStoMessage() */
                /* Delete a per-query context using delAddrQID() and putNSQID() */
                if (parsed.dh->aa) {
                    char** nsIP; char** nsDomain;
                    uint16_t qid = parsed.dh->id;

                    getNSbyQID(context, qid, nsIP, nsDomain);
                    getAddrbyQID(context, qid, (struct sockaddr* )&client_addr);

                    uint64_t new_len = TDNSPutNStoMessage(buffer, recv_len, parsed, *nsIP, *nsDomain);
                    // TODO: do we send BUFFER_SIZE? or just recv_len because didn't we just append to buffer
                    ssize_t send_len = sendto(sockfd, buffer, new_len, 0,
                                                  (struct sockaddr *)&client_addr, client_len);
                    if (send_len < 0) {
                        perror("Sendto failed");
                    }
                    delAddrQID(context, qid);
                    delNSQID(context, qid);
                }

                /* 7-1. If the message is a non-authoritative response */
                /* (i.e., it contains referral to another nameserver) */
                /* send an iterative query to the corresponding nameserver */
                /* You can extract the query from the response using TDNSGetIterQuery() */
                /* You should update a per-query context using putNSQID() */
                else {

                }
            }

            else {
                // ERROR: SHOULD NEVER REACH THIS PART
            }
        }
    }
    close(sockfd);
    return 0;
}

