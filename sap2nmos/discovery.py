"""Unicast DNS-SD discovery of NMOS registries (IS-04 / BCP-003)."""

import socket
import sys

import dns.exception
import dns.resolver

SERVICES = ("_nmos-register._tcp", "_nmos-registration._tcp")
SUPPORTED_VERSIONS = ("v1.3", "v1.2", "v1.1", "v1.0")


def system_search_domains():
    """DNS search domains configured on this machine."""
    domains = []
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
            for name in ("SearchList", "Domain", "DhcpDomain"):
                try:
                    value = winreg.QueryValueEx(key, name)[0]
                    domains += [d.strip() for d in value.split(",")]
                except OSError:
                    pass
        except OSError:
            pass
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if parts and parts[0] in ("search", "domain"):
                        domains += parts[1:]
        except OSError:
            pass

    unique = []
    for d in domains:
        d = d.strip().rstrip(".")
        if d and d not in unique:
            unique.append(d)
    return unique


def _make_resolver(nameserver=""):
    if nameserver:
        resolver = dns.resolver.Resolver(configure=False)
        host, _, port = nameserver.partition(":")
        resolver.nameservers = [socket.gethostbyname(host)]
        resolver.port = int(port or 53)
    else:
        resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    return resolver


def _txt_map(resolver, name):
    txt = {}
    try:
        for record in resolver.resolve(name, "TXT"):
            for raw in record.strings:
                key, _, value = raw.decode(errors="ignore").partition("=")
                txt[key] = value
    except dns.exception.DNSException:
        pass
    return txt


def discover_registries(domain="", nameserver=""):
    """Query PTR/SRV/TXT for NMOS registration services.

    Returns candidates sorted by priority (lowest first), each:
    {name, url, host, port, proto, versions, priority, domain}
    """
    resolver = _make_resolver(nameserver)
    domains = [domain.rstrip(".")] if domain else system_search_domains()
    found = {}

    for dom in domains:
        for service in SERVICES:
            try:
                ptrs = resolver.resolve(f"{service}.{dom}", "PTR")
            except dns.exception.DNSException:
                continue
            for ptr in ptrs:
                instance = ptr.target
                try:
                    srv = next(iter(resolver.resolve(instance, "SRV")))
                except (dns.exception.DNSException, StopIteration):
                    continue
                txt = _txt_map(resolver, instance)

                host = str(srv.target).rstrip(".")
                port = srv.port
                proto = txt.get("api_proto", "http")
                versions = [v for v in txt.get("api_ver", "v1.3").split(",") if v]
                version = next((v for v in SUPPORTED_VERSIONS if v in versions), "v1.3")
                try:
                    priority = int(txt.get("pri", srv.priority))
                except ValueError:
                    priority = srv.priority

                # If the SRV target doesn't resolve locally (host not in the
                # client's search path), fall back to its A record.
                try:
                    socket.getaddrinfo(host, port)
                except OSError:
                    try:
                        host = next(iter(resolver.resolve(host, "A"))).to_text()
                    except (dns.exception.DNSException, StopIteration):
                        continue

                url = f"{proto}://{host}:{port}/x-nmos/registration/{version}"
                found[url] = {
                    "name": str(instance).rstrip("."),
                    "url": url,
                    "host": host,
                    "port": port,
                    "proto": proto,
                    "versions": versions,
                    "priority": priority,
                    "domain": dom,
                }

    return sorted(found.values(), key=lambda c: c["priority"])
