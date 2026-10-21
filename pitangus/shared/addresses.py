"""Whether an IP address is publicly routable, for the SSRF checks on destinations an admin types in.

`ipaddress.is_global` alone isn't enough for IPv6 forms that carry an IPv4 address: on an IPv6-only network with
DNS64/NAT64, `64:ff9b::a00:1` is `is_global` but the translator delivers it to 10.0.0.1. The answer also varies across
the Python versions we support (3.12 patch releases changed the IPv6 special-purpose table), so these forms are decided
here explicitly.
"""

from __future__ import annotations

import ipaddress

NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")  # RFC 6052: the IPv4 address is the last 32 bits
NAT64_LOCAL_USE = ipaddress.IPv6Network("64:ff9b:1::/48")  # RFC 8215: where the IPv4 sits is up to the operator
IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")  # RFC 4291, deprecated


def is_public(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when `address` (an IPv6 zone suffix is ignored) and every IPv4 address it embeds are global.
    Anything unparsable is not public."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0] if isinstance(address, str) else address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return ip.is_global
    if ip.ipv4_mapped:
        return ip.ipv4_mapped.is_global
    if ip in NAT64_LOCAL_USE or ip in IPV4_COMPATIBLE:
        return False
    if ip in NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF).is_global
    embedded = [ip.sixtofour] if ip.sixtofour else list(ip.teredo or ())
    return ip.is_global and all(item.is_global for item in embedded)
