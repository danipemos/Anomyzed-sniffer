import hmac
import hashlib
from scapy.all import *
import re
import configparser

mac_mapping = {}
counter = 1
config=configparser.ConfigParser()
config.read('config.ini')
hashIpv6=config.get('General','HashMAC',fallback='Secreto')

def hash(packet):
    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        
        hashed_mac_src = hmac.new(b'secreto', mac_src.encode(), hashlib.sha256).hexdigest()
        hashed_mac_dst = hmac.new(b'secreto', mac_dst.encode(), hashlib.sha256).hexdigest()
        
        packet[Ether].src = ':'.join(hashed_mac_src[i:i+2] for i in range(0, 12, 2))
        packet[Ether].dst = ':'.join(hashed_mac_dst[i:i+2] for i in range(0, 12, 2))
    return packet

def int_to_mac(macint):
    return  ":".join(re.findall("..", "%012x"%macint))

def map(packet):
    global counter
    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        
        if mac_src not in mac_mapping:
            mac_mapping[mac_src] = int_to_mac(counter)
            counter += 1
        packet[Ether].src = mac_mapping[mac_src]
        
        if mac_dst not in mac_mapping:
            mac_mapping[mac_dst] = int_to_mac(counter)
            counter += 1
        packet[Ether].dst = mac_mapping[mac_dst]
    return packet

def zero(packet):
    if Ether in packet:
        packet[Ether].src = '00:00:00:00:00:00'
        packet[Ether].dst = '00:00:00:00:00:00'
    return packet

modesMac = {
    "map": map,
    "hash": hash,
    "zero": zero,
}