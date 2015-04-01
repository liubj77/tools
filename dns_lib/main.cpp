// Filename: main.cpp
// Author: liubj77 - liubj77@gmail.com

#include <stdio.h>
#include "tools/dns_lib/dns.h"

using namespace tools;

int main()
{
    DnsResource *rr = NULL;

    DnsQuery dns_query;

    printf("Query T_A of www domain\n");
    int ret = dns_query.dns_lookup("www.baidu.com", T_A, &rr);
    dns_resource_print(rr);
    dns_resource_free(rr);

    printf("Query T_MX of mail domain\n");
    ret = dns_query.dns_lookup("163.com", T_MX, &rr);
    dns_resource_print(rr);
    dns_resource_free(rr);

    printf("Query T_A of mx domain\n");
    ret = dns_query.dns_lookup("163mx03.mxmail.netease.com", T_A, &rr);
    dns_resource_print(rr);
    dns_resource_free(rr);

    printf("Query T_A of mail domain\n");
    ret = dns_query.dns_mx_lookup("163.com", &rr);
    dns_resource_print(rr);
    dns_resource_free(rr);

    return 0;
}
