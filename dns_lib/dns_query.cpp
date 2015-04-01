// Filename: dns.cpp
// Author: liubj77 - liubj77@gmail.com

#include <stdio.h>
#include <ctype.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include "tools/dns_lib/dns_query.h"
#include "tools/dns_lib/dns_util.h"

extern struct __res_state _res;

namespace tools {

DnsQuery::DnsQuery() {
}

DnsQuery::~DnsQuery() {
}

int DnsQuery::dns_lookup(const char *name, unsigned type, DnsResource **rrlist)
{
    char cname[DNS_NAME_LEN];
    int c_len = sizeof cname;
    static DnsReply reply;
    int ret = -1;

    const char *origin_name = name;

    if (rrlist) {
        *rrlist = NULL;
    }

    for (int i = 0; i < 10; ++i) {
        // dns query and store result in reply struct
        if ((ret = dns_query(name, type, &reply)) != DNS_OK) {
            return ret;
        }

        ret = dns_extract_answer(origin_name, &reply, type, rrlist, cname, c_len);
        switch (ret) {
        case DNS_OK:
            return DNS_OK;
        case DNS_RECURSE:
            name = cname;
            break;
        default:
            fprintf(stderr, "name service error for name=%s type=%s", name, dns_strtype(type));
            return ret;
        }
    }

    return DNS_NOTFOUND;
}

int DnsQuery::dns_mx_lookup(const char *name, DnsResource **rrlist)
{
    if (rrlist) {
        *rrlist = NULL;
    }

    DnsResource *mx_list = NULL;
    int ret;

    ret = dns_lookup(name, T_MX, &mx_list);
    if (ret != DNS_OK) {
        return ret;
    }
    
    // sort asc by pref
    mx_list = dns_resource_sort(mx_list);
    for (DnsResource *rr = mx_list; rr; rr = rr->next) {
        if (rr->type != T_MX) {
            fprintf(stderr, "dns_mx_lookup: bad resource type: %s\n", dns_strtype(rr->type));
            return DNS_FAIL;
        }

        // then get ip of mx record
        DnsResource *mx_ip_list;
        if ((ret = dns_lookup((const char*)rr->data, T_A, &mx_ip_list)) != DNS_OK) {
            return ret;
        } else {
            for (DnsResource *temp = mx_ip_list; temp; temp = temp->next) {
                temp->pref = rr->pref;
            }

            *rrlist = dns_resource_append(*rrlist, mx_ip_list);
        }
    }

    dns_resource_free(mx_list);

    return DNS_OK;
}

int DnsQuery::dns_query(const char *name, unsigned type, DnsReply *reply)
{   
    HEADER *reply_header;
    size_t len;

    if (reply->buf == NULL) {
        reply->buf = (unsigned char *)malloc(DEF_DNS_REPLY_SIZE);
        reply->buf_len = DEF_DNS_REPLY_SIZE;
    }

    if ((_res.options & RES_INIT) == 0 && res_init() < 0) {
        return DNS_FAIL;
    }

    /* perform the lookup */
    for (;;) {
        len = res_search((char*)name, C_IN, type, reply->buf, reply->buf_len);
        reply_header = (HEADER*) reply->buf;
        reply->rcode = reply_header->rcode;
        if (len < 0) { // some error happened
            switch (h_errno) {
            case NO_RECOVERY:
                return DNS_FAIL;
            case HOST_NOT_FOUND:
            case NO_DATA:
                return DNS_NOTFOUND;
            default:
                return DNS_RETRY;
            }
        }

        // tc is 0, indicate message not truncated, only udp can trucate message
        if (reply_header->tc == 0 || reply->buf_len >= MAX_DNS_REPLY_SIZE) {
            break;
        }

        reply->buf = (unsigned char*) realloc((char*)reply->buf, 2 * reply->buf_len);
        reply->buf_len *= 2;
    }

    if (len > reply->buf_len) {
        len = reply->buf_len;
    }

    reply->end = reply->buf + len;
    reply->query_start = reply->buf + sizeof(HEADER);
    reply->answer_start = 0;
    reply->query_count = ntohs(reply_header->qdcount);
    reply->answer_count = ntohs(reply_header->ancount);

    return DNS_OK;
}

int DnsQuery::dns_extract_answer(const char *origin_name, DnsReply *reply, int type, 
                                 DnsResource **rrlist, char *cname, int c_len)
{
    char rr_name[DNS_NAME_LEN];
    int query_count, answer_count;
    DnsFixed fixed;
    DnsResource *rr;
    int len;
    int ret;
    unsigned char *pos;
    int resource_found = 0, cname_found = 0;
    int not_found_status = DNS_NOTFOUND;

    /* skip queries */
    if (reply->answer_start == 0) {
        query_count = reply->query_count;
        pos = reply->query_start;

        while (query_count-- > 0) {
            if (pos >= reply->end) {
                return DNS_RETRY;
            }

            len = dn_expand(reply->buf, reply->end, pos, rr_name, DNS_NAME_LEN);
            if (len < 0) {
                return DNS_RETRY;
            }
            pos += len + QFIXEDSZ;
        }

        reply->answer_start = pos;
    }

    // next is dns response answer
    answer_count = reply->answer_count;
    pos = reply->answer_start;

///////////////////////////////////////////
#define FREE_AND_RETURN(status) {   \
    if (rrlist && *rrlist) {        \
        dns_resource_free(*rrlist);       \
        *rrlist = NULL;             \
    }                               \
    return status;                  \
}
///////////////////////////////////////////
    // extract answer
    while (answer_count-- > 0) {
        if (pos >= reply->end) {
            FREE_AND_RETURN(DNS_RETRY);
        }

        len = dn_expand(reply->buf, reply->end, pos, rr_name, DNS_NAME_LEN);
        if (len < 0) {
            FREE_AND_RETURN(DNS_RETRY);
        }
        pos += len;
        // extract the fixed reply data: type, class, ttl, length
        if (pos + RRFIXEDSZ > reply->end) {
            FREE_AND_RETURN(DNS_RETRY);
        }
        if ((ret = dns_get_fixed(pos, &fixed)) != DNS_OK) {
            FREE_AND_RETURN(ret);
        }
        pos += RRFIXEDSZ;

        if (pos + fixed.length > reply->end) {
            FREE_AND_RETURN(DNS_RETRY);
        }

        // extract answer raw data
        if (type == fixed.type || type == T_ANY) {
            /* request type */
            if (rrlist) {
                if ((ret = dns_get_resource(&rr, origin_name, reply, pos, rr_name, &fixed)) 
                        == DNS_OK) {
                    ++ resource_found;
                    *rrlist = dns_resource_append(*rrlist, rr);
                } else if (not_found_status != DNS_RETRY) {
                    not_found_status = ret;
                }
            } else {
                ++resource_found;
            }
        } else if (fixed.type == T_CNAME) {
            ++cname_found;
            if (cname && c_len > 0) {
                // get cname info 
                if (dn_expand(reply->buf, reply->end, pos, cname, c_len) < 0) {
                    FREE_AND_RETURN(DNS_RETRY);
                }
            }
        }

        pos += fixed.length;
    }

    if (resource_found) {
        return DNS_OK;
    }

    if (cname_found) {
        return DNS_RECURSE;
    }

    return not_found_status;
}

int DnsQuery::dns_get_fixed(unsigned char *pos, DnsFixed *fixed)
{
    GETSHORT(fixed->type, pos);
    GETSHORT(fixed->uclass, pos);
    GETLONG(fixed->ttl, pos);
    GETSHORT(fixed->length, pos);
    
    if (fixed->uclass != C_IN) {
        return DNS_RETRY;
    }

    return DNS_OK;
}

int DnsQuery::dns_get_resource(DnsResource **rrlist, const char *origin_name,
                               DnsReply *reply, unsigned char *pos,
                               char *rr_name, DnsFixed *fixed)
{
    char temp[DNS_NAME_LEN];
    ssize_t data_len;
    unsigned pref = 0;
    unsigned char *src;
    unsigned char *dst;
    int ch;

    *rrlist = NULL;

#define MIN2(a, b)  ((unsigned)(a) < (unsigned)(b) ? (a) : (b))
#define ISPRINT(c)  (isascii((unsigned char)(c)) && isprint((unsigned char)(c)))

    switch (fixed->type) {
    case T_CNAME:
    case T_MB:
    case T_MG:
    case T_MR:
    case T_NS:
    case T_PTR:
        if (dn_expand(reply->buf,reply->end, pos, temp, sizeof(temp)) < 0) 
            return DNS_RETRY;
        data_len = strlen(temp) + 1;
        break;
    case T_MX:
        GETSHORT(pref, pos);
        if (dn_expand(reply->buf, reply->end, pos, temp, sizeof(temp)) < 0) 
            return DNS_RETRY;
        data_len = strlen(temp) + 1;
        break;
    case T_A:
        if (fixed->length != INET_ADDR_LEN)
            return DNS_RETRY;
        if (fixed->length > sizeof(temp))
            return DNS_FAIL;
        memcpy(temp, pos, fixed->length);
        data_len = fixed->length;
        break;
    case T_TXT:
        data_len = MIN2(pos[0] + 1, MIN2(fixed->length + 1, sizeof(temp)));
        for (src = pos + 1, dst = (unsigned char *) (temp);
                dst < (unsigned char *) (temp) + data_len - 1; /* */) {
            ch = *src++;
            *dst++ = (ISPRINT(ch) ? ch : ' ');
        }
        *dst = 0;
        break;
    default:
        return DNS_FAIL;
    }

    *rrlist = dns_resource_create(origin_name, rr_name, fixed->type, fixed->uclass,
                        fixed->ttl, pref, temp, data_len);

    return DNS_OK;
}


}
