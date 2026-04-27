#include "network_utils.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <set>

std::vector<std::string> get_network_interfaces()
{
    std::vector<std::string> result;
    std::set<std::string> unique;

    struct ifaddrs* ifaddr = nullptr;

    if (getifaddrs(&ifaddr) == -1)
        return result;

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_name)
            continue;

        std::string name = ifa->ifa_name;

        if (name == "lo")
            continue;

        unique.insert(name);
    }

    freeifaddrs(ifaddr);

    result.assign(unique.begin(), unique.end());
    return result;
}