// Filename: dns_util.cpp
// Author: liubj77 - liubj77@gmail.com

#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include "tools/dns_lib/dns_util.h"

namespace tools {

static struct DnsTypeMap dns_type_map[] = {
    { T_A, "A" },
    { T_AAAA, "AAAA" },
    { T_NS, "NS" },
    { T_MD, "MD" },
    { T_MF, "MF" },
    { T_CNAME, "CNAME" },
    { T_SOA, "SOA" },
    { T_MB, "MB" },
    { T_MG, "MG" },
    { T_MR, "MR" },
    { T_NULL, "NULL" },
    { T_WKS, "WKS" },
    { T_PTR, "PTR" },
    { T_HINFO, "HINFO" },
    { T_MINFO, "MINFO" },
    { T_MX, "MX" },
    { T_TXT, "TXT" },
    { T_RP, "RP" },
    { T_AFSDB, "AFSDB" },
    { T_X25, "X25" },
    { T_ISDN, "ISDN" },
    { T_RT, "RT" },
    { T_NSAP, "NSAP" },
    { T_NSAP_PTR, "NSAP_PTR" },
    { T_SIG, "SIG" },
    { T_KEY, "KEY" },
    { T_PX, "PX" },
    { T_GPOS, "GPOS" },
    { T_LOC, "LOC" },
    { T_AXFR, "AXFR" },
    { T_MAILB, "MAILB" },
    { T_MAILA, "MAILA" },
    { T_ANY, "ANY" },
};

const char *dns_strtype(unsigned type) 
{
    static const char *unknown = "unknown error";

    for (unsigned i = 0; i < sizeof(dns_type_map) / sizeof(dns_type_map[0]); ++i) {
        if (dns_type_map[i].type == type) {
            return dns_type_map[i].text;
        }
    }

    return unknown;
}

DnsResource *dns_resource_create(const char *qname, const char *rname, 
        unsigned short type, unsigned short uclass, unsigned int ttl,
        unsigned pref, const char *data, size_t data_len)
{
    DnsResource *rr;
    rr = (DnsResource *)malloc(sizeof(DnsResource) + data_len - 1);
    rr->qname = strdup(qname);
    rr->rname = strdup(rname);
    rr->type  = type;
    rr->uclass = uclass;
    rr->dnssec_valid = 0;
    rr->pref = pref;
    if (data && data_len > 0) {
        memcpy(rr->data, data, data_len);
    }
    rr->data_len = data_len;
    rr->next = NULL;

    return rr;
}

DnsResource *dns_resource_append(DnsResource *rlist, DnsResource *rr) 
{
    if (rlist == NULL) {
        rlist = rr;
    } else {
        rlist->next = dns_resource_append(rlist->next, rr);
    }

    return rlist;
}

void dns_resource_free(DnsResource *rr)
{
    if (rr) {
        if (rr->next) {
            dns_resource_free(rr->next);
        }

        free(rr->qname);
        free(rr->rname);
        free((char*)rr);
    }
}

static int dns_resource_sort_compare(const void *a, const void *b)
{
    DnsResource *aa = *(DnsResource **)a;
    DnsResource *bb = *(DnsResource **)b;

    if (aa->pref != bb->pref) {
        return aa->pref - bb->pref;
    }

    return 0;
}

DnsResource *dns_resource_sort(DnsResource *list)
{
    DnsResource **rr_array;
    DnsResource *rr;
    int len;
    int i;

    /* get list len */
    for (len = 0, rr = list; rr != 0; len++, rr = rr->next);

    rr_array = (DnsResource **)malloc(len * sizeof(DnsResource*));
    for (len = 0, rr = list; rr != 0; len++, rr = rr->next) {
        rr_array[len] = rr;
    }

    qsort((char *) rr_array, len, sizeof(*rr_array), dns_resource_sort_compare);

    for (i = 0; i < len - 1; i++) {
        rr_array[i]->next = rr_array[i + 1];
    }
    rr_array[i]->next = 0;
    list = rr_array[0];
    
    // clean up
    free((char*)rr_array);

    return list;
}

static const char *dns_resource_to_pa(DnsResource *rr, MAI_HOSTADDR_STR *host)
{
    if (rr->type == T_A) {
        return (inet_ntop(AF_INET, rr->data, host->buf, sizeof(host->buf)));
    } else if (rr->type == T_AAAA) {
        return (inet_ntop(AF_INET, rr->data, host->buf, sizeof(host->buf)));
    } else {
        errno = EAFNOSUPPORT;
        return 0;
    }
}

void dns_resource_print(DnsResource *rr)
{
    MAI_HOSTADDR_STR host;
    while (rr) {
        printf("%s: ad: %u, ttl: %9u ", rr->rname, rr->dnssec_valid, rr->ttl);
        switch (rr->type) {
        case T_A:
        case T_AAAA:
            if (dns_resource_to_pa(rr, &host) == 0) {
                fprintf(stderr, "conversion error for resource record type: %s",
                        dns_strtype(rr->type));
            }
            printf("%s  pref: %9u : %s\n", dns_strtype(rr->type), rr->pref, host.buf);
            break;
        case T_CNAME:
        case T_MB:
        case T_MG:
        case T_MR:
        case T_NS:
        case T_PTR:
        case T_TXT:
            printf("%s: %s\n", dns_strtype(rr->type), rr->data);
            break;
        case T_MX:
            printf("pref: %d %s: %s\n",rr->pref, dns_strtype(rr->type), rr->data);
            break;
        default:
            printf("print_rr: don't know how to print type %s",dns_strtype(rr->type));
        
        }
        rr = rr->next;
    }
}


} /* namespace tools */
