// Filename: dns_util.h
// Author: liubj77 - liubj77@gmail.com

#ifndef  _DNS_UTIL_H_
#define  _DNS_UTIL_H_

#include "tools/dns_lib/dns_query.h"

namespace tools {

#ifdef HAS_IPV6
# define MAI_HOSTADDR_STRSIZE   INET6_ADDRSTRLEN
#else
# ifndef INET_ADDRSTRLEN
#  define INET_ADDRSTRLEN   16
# endif
# define MAI_HOSTADDR_STRSIZE   INET_ADDRSTRLEN
#endif

typedef struct {
    char buf[MAI_HOSTADDR_STRSIZE];
} MAI_HOSTADDR_STR;

struct DnsTypeMap {
    unsigned type;
    const char *text;
};

const char *dns_strtype(unsigned type);

DnsResource *dns_resource_create(const char *qname, const char *rname,
        unsigned short type, unsigned short uclass, unsigned int ttl,
        unsigned pref, const char *data, size_t data_len);

DnsResource *dns_resource_sort(DnsResource *list);

DnsResource *dns_resource_append(DnsResource *rlist, DnsResource *rr);

void dns_resource_free(DnsResource *rr);

void dns_resource_print(DnsResource *rr);

} /* namespace tools */

#endif //DNS_UTIL_H_

