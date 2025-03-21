from scapy.all import *
import hashlib
import ipaddress
import configparser

ipv6_mapping = {}
counter = 1
config=configparser.ConfigParser()
config.read('config.ini')
hashIpv6=config.get('General','HashIpv6',fallback='Secreto')

def hash(packet):
    if IPv6 in packet:
        ip_org = packet[IPv6].src
        ip_dst = packet[IPv6].dst
        
        hashed_ip_src = hmac.new(hashIpv6.encode(), ip_org.encode(), hashlib.sha256).hexdigest()
        hashed_ip_dst = hmac.new(hashIpv6.encode(), ip_dst.encode(), hashlib.sha256).hexdigest()

        packet[IPv6].src = ipaddress.IPv6Address(int(hashed_ip_src[:32], 16))
        packet[IPv6].dst = ipaddress.IPv6Address(int(hashed_ip_dst[:32], 16))

    return packet

def map(packet):
    global counter
    if IPv6 in packet:
        ip_org = packet[IPv6].src
        ip_dst = packet[IPv6].dst
        if ip_org not in ipv6_mapping:
            ipv6_mapping[ip_org] = ipaddress.IPv6Address(counter)
            counter += 1
        packet[IPv6].src = ipv6_mapping[ip_org]
        if ip_dst not in ipv6_mapping:
            ipv6_mapping[ip_dst] = ipaddress.IPv6Address(counter)
            counter += 1
        packet[IPv6].dst = ipv6_mapping[ip_dst]
    return packet  

def zero(packet):
    if IPv6 in packet:
        packet[IPv6].src = ipaddress.IPv6Address(0)
        packet[IPv6].dst = ipaddress.IPv6Address(0)
    return packet  

modes6 = {
    "map": map,
    "hash": hash,
    "zero": zero,
}

