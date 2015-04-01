// Filename: dns.h
// Author: liubj77 - liubj77@gmail.com

#ifndef  _TOOLS_DNS_LIB_DNSQUERY_H_
#define  _TOOLS_DNS_LIB_DNSQUERY_H_

#include <arpa/nameser.h>

namespace tools {

enum DnsError {
    DNS_OK = 0,
    DNS_RECURSE = -1,
    DNS_RETRY   = -2,
    DNS_NOTFOUND   = -3,
    DNS_FAIL  = -4,
    DNS_INVAL = -5,
};


#ifndef INET_ADDR_LEN
#define INET_ADDR_LEN 4
#endif

#ifndef INET6_ADDR_LEN
#define INET6_ADDR_LEN 16
#endif

#define DEF_DNS_REPLY_SIZE 4096   /* in case using tcp */
#define MAX_DNS_REPLY_SIZE 65536
#define DNS_NAME_LEN 1024

typedef struct DnsResource {
    char *qname;            /* query name, strdup() */
    char *rname;            /* reply anme */
    unsigned short type;    /* T_A, T_CAME, etc */
    unsigned short uclass;  /* C_IN, etc */
    unsigned int ttl;       /* always */
    unsigned int dnssec_valid;      /* DNSSEC validated */
    unsigned short pref;    /* T_MX only */
    struct DnsResource *next;   /* link */
    size_t data_len;        /* actual data size */
    char data[1];           /* actual a bunch of data */
} DnsResource;

typedef struct DnsReply {
    unsigned char *buf;     /* raw reply data */
    size_t buf_len;         /* reply buffer len */
    int rcode;              /* unfiltered reply code */
    int query_count;        /* number of queres */
    int answer_count;       /* number of answers */
    unsigned char *query_start;  /* start of qeury data */
    unsigned char *answer_start; /* start of answer data */
    unsigned char* end;          /* first byte past reply */
} DnsReply;

typedef struct DnsFixed {
    unsigned short type;    /* T_A, T_CNAME, etc */
    unsigned short uclass;  /* C_IN, etc */
    unsigned int ttl;
    unsigned length;        /* record length */
} DnsFixed;

class DnsQuery {
public:
    DnsQuery();
    ~DnsQuery();

    int dns_lookup(const char *name, unsigned type, DnsResource **rrlist);

    int dns_mx_lookup(const char *name, DnsResource **rrlist);

private:
    int dns_query(const char *name, unsigned type, DnsReply *reply);

    int dns_extract_answer(const char *origin_name, DnsReply *reply, int type,
            DnsResource **rrlist, char *cname, int c_len);

    int dns_get_fixed(unsigned char *pos, DnsFixed *fixed);

    int dns_get_resource(DnsResource **rrlist, const char *origin_name,
            DnsReply *reply, unsigned char *pos,
            char *rr_name, DnsFixed *fixed);

};


} /* namespace tools */

#endif //DNS_H_

