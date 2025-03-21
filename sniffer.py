from scapy.all import *
import hashlib
import hmac
import argparse
import time
import os
import signal
import sys
import threading
import ipaddress
import configparser
import pcapy
from ctypes import *
import IPv6_modes
import Mac_modes
import pyzipper
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
import send
import argparse

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts_sec", ctypes.c_long),
                ("ts_usec", ctypes.c_long),
                ("caplen", ctypes.c_uint),
                ("len", ctypes.c_uint)]

class Packet(ctypes.Structure):
    _fields_ = [("header", pcap_pkthdr),
                ("data", ctypes.POINTER(ctypes.c_ubyte))]

ip_mapping = {}
counter = 1
start_time = time.time()
packet_counter=defaultdict(int)
total_bytes=0
last_pcap_time=time.time()
session_dict={}
event = threading.Event()
packetQueue=queue.Queue()
cipher_event= threading.Event()
def get_pcap_name():
    return f"capture_{time.strftime('%Y%m%d_%H%M%S', time.localtime())}.pcap"

pcap_filename=get_pcap_name()
PcapWriter(pcap_filename,sync=True)

def rotation():
    global last_pcap_time,pcap_filename
    while not event.is_set() or not sni.empty():
        if (size) and (os.path.exists(pcap_filename) and (os.path.getsize(pcap_filename)) > size):
            last_pcap_name=pcap_filename
            pcap_filename=get_pcap_name()
            if rotate:
                last_pcap_time=time.time()
            filename=ciphers_modes.get(cipher)(last_pcap_name)
            #for loc in location:
                #send.send_modes.get(loc)(filename)
        if rotate and ((time.time()-last_pcap_time)>rotate):
            pcap_filename=get_pcap_name()
            last_pcap_time=time.time()
            filename=ciphers_modes.get(cipher)(last_pcap_name)
            #for loc in location:
                #send.send_modes.get(loc)(filename)
        if packages_pcap and (os.path.exists(pcap_filename) and (count_packets_pcap()>= packages_pcap)):
            pcap_filename=get_pcap_name()
            if rotate:
                last_pcap_time=time.time()
            filename=ciphers_modes.get(cipher)(last_pcap_name)
            #for loc in location:
                #send.send_modes.get(loc)(filename)
            #TODO poner que si tiene DISK especificado en la lista no se borre y si no esta que se borre
        time.sleep(0.01)
    filename=ciphers_modes.get(cipher)(pcap_filename)
    #for loc in location:
        #send.send_modes.get(loc)(filename)
    cipher_event.set()


def pcap_zip(pcap_name):
    password='secreto'
    zip_name= os.path.splitext(pcap_name)[0]+".zip"
    with pyzipper.AESZipFile(zip_name, 'w',compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES,allowZip64=True) as zip_file:
        zip_file.setpassword(password.encode())
        zip_file.write(pcap_name,arcname=os.path.basename(pcap_name))
    os.remove(pcap_name)
    return zip_name

def pcap_gpg(pcap_name):
    key=get_random_bytes(32)
    encripted_file= os.path.splitext(pcap_name)[0]+"/encripted.pcap"
    with open(pcap_name, 'rb') as pcap:
        data=pcap.read()
    os.makedirs(os.path.splitext(pcap_name)[0])

    iv=get_random_bytes(AES.block_size)
    cipher=AES.new(key, AES.MODE_CBC, iv)
    data_filled=pad(data,AES.block_size)
    encrypted_data=cipher.encrypt(data_filled)
    iv_file=os.path.splitext(pcap_name)[0]+"/iv.bin"

    with open(iv_file ,'w')as iv_file:
        iv_file.write(iv.hex())

    with open(encripted_file, 'wb') as encripted:
        encripted.write(encrypted_data)

    cipher=PKCS1_v1_5.new(public_key)
    encrypted_key=cipher.encrypt(key)

    encrypted_key_file = os.path.splitext(pcap_name)[0]+'/'+'encrypted_key.bin'
    with open(encrypted_key_file,'wb') as encripted_key_file:
        encripted_key_file.write(encrypted_key)
    
    with pyzipper.ZipFile("encrypted_"+os.path.splitext(pcap_name)[0]+".zip",'w',compression=pyzipper.ZIP_DEFLATED,allowZip64=True) as zip:
        for file in os.listdir(os.path.splitext(pcap_name)[0]+"/"):
            zip.write(os.path.splitext(pcap_name)[0]+"/"+file,arcname=file)
            os.remove(os.path.splitext(pcap_name)[0]+"/"+file)

    os.removedirs(os.path.splitext(pcap_name)[0]+"/")
    os.remove(pcap_name)
    return os.path.splitext(pcap_name)[0]+".zip"

ciphers_modes={
    "ZIP" : pcap_zip,
    "GPG" : pcap_gpg,
    "none" : lambda pcap_name : pcap_name
}


def count_packets_pcap():
    global pcap_filename
    count=0
    cap = pcapy.open_offline(pcap_filename)
    while True:
        try:
            (hdr, pkt) = cap.next()
            if not hdr:
                break
            count+=1
        except pcapy.PcapError:
            break
    return count

def hash(packet):
    if IP in packet:
        ip_org = packet[IP].src
        ip_dst = packet[IP].dst
        hashed_ip_src = hmac.new(hashipv4.encode(), ip_org.encode(), hashlib.sha256).hexdigest()
        hashed_ip_dst = hmac.new(hashipv4.encode(), ip_dst.encode(), hashlib.sha256).hexdigest()
        packet[IP].src = ipaddress.IPv4Address(int(hashed_ip_src[:8],16))
        packet[IP].dst = ipaddress.IPv4Address(int(hashed_ip_dst[:8],16))
    return packet  

def map(packet):
    global counter
    if IP in packet:
        ip_org = packet[IP].src
        ip_dst = packet[IP].dst
        if ip_org not in ip_mapping:
            ip_mapping[ip_org] = counter
            counter += 1
        packet[IP].src = ip_mapping[ip_org]
        if ip_dst not in ip_mapping:
            ip_mapping[ip_dst] = counter
            counter += 1
        packet[IP].dst = ip_mapping[ip_dst]
    return packet  

def zero(packet):
    if IP in packet:
        packet[IP].src = 0
        packet[IP].dst = 0
    return packet  

anon = {
    "map": map,
    "hash": hash,
    "zero": zero,
}
headers = {
    "ip": [IP],
    "ipv6": [IPv6],
    "network": [IP,IPv6],
    "tcp": [TCP],
    "udp": [UDP],
    "icmp": [ICMP],
    "transport": [TCP, UDP, ICMP],
    "dns": [DNS],
    "none": [],
}

protocol_list=[IP,IPv6,UDP,TCP,ICMP,DNS]

def procces_packet(packet):
    global pcap_filename
    global total_bytes
    total_bytes+=len(packet)
    global packet_counter,last_pcap_time
    packet_counter["Total Packets"]+=1
    src_ip = None
    dst_ip = None
    if "MAC" in protocols:
        packet=Mac_modes.modesMac.get(macmode)(packet)
    if IP in packet:
        if "IP" in protocols:
            packet = anon.get(mode)(packet)
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
    if IPv6 in packet:
        if "IPv6" in protocols:
            packet = IPv6_modes.modes6.get(ipv6mode)(packet)
        src_ip = packet["IPv6"].src
        dst_ip = packet["IPv6"].dst
    if src_ip and dst_ip:
        for protocol in headers["transport"]:
            if protocol in packet:
                protocol_name=protocol.__name__
                src_port = ":"+str(packet.sport) if packet.haslayer(TCP) or packet.haslayer(UDP) else ""
                dst_port = ":"+str(packet.dport) if packet.haslayer(TCP) or packet.haslayer(UDP) else ""
                key = protocol_name,src_ip,src_port,dst_ip,dst_port
                inverse_key=protocol_name,dst_ip,dst_port,src_ip,src_port
                if key not in session_dict and inverse_key not in session_dict:
                    session_dict[key] = {"packet count": 0, "total_size": 0}
                if key in session_dict:
                    session_dict[key]["packet count"] += 1
                    session_dict[key]["total_size"] += len(packet)
                else:
                    session_dict[inverse_key]["packet count"] += 1
                    session_dict[inverse_key]["total_size"] += len(packet)
        header_del_list = headers.get(header_ptr)
        for protocol in protocol_list:
            if protocol in packet:
                packet_counter[f"Total Packets {protocol.__name__}"] += 1  
                if protocol in header_del_list :
                    packet[protocol].remove_payload()
    wrpcap(pcap_filename,packet,append=True,sync=True)
    
def format_time(seconds):
    hrs, rem = divmod(seconds, 3600)
    mins, secs = divmod(rem, 60)
    return f"{int(hrs):02}:{int(mins):02}:{int(secs):02}"

def stadistics():
    global last_pcap_time,pcap_filename
    while not event.is_set() or not sni.empty():
        os.system('clear')
        elapsed_time = time.time() - start_time
        for header_ptr,packet_count in list(packet_counter.items()):
            print(f"{header_ptr}: {packet_count}")
        print(f"Total time: {format_time(elapsed_time)}")
        print(f"Total Megabytes: {total_bytes/ 1048576:.2f}")
        if elapsed_time > 0:
            bandwidth = (total_bytes * 8) / elapsed_time / 1048576
            print(f"Ancho de banda medio: {bandwidth:.2f} Mbps")
        for session_key,session_data in list(session_dict.items()):
            print(f"{session_key[0]} {session_key[1]}{session_key[2]} > {session_key[3]}{session_key[4]} Total packages: {session_data['packet count']} Total data in KB: {session_data['total_size']/ 1024:.2f}")
        time.sleep(0.01)


def count_packets_pcap():
    global pcap_filename
    count=0
    cap = pcapy.open_offline(pcap_filename)
    while True:
        try:
            (hdr, pkt) = cap.next()
            if not hdr:
                break
            count+=1
        except pcapy.PcapError:
            break
    return count

contador=0
def packet_thread():
    global contador
    while not event.is_set() or not sni.empty():
        packet_ptr=sni.dequeue()
        if packet_ptr:
            packet = packet_ptr.contents
            header=packet.header
            data_len = header.len
            data_ptr=packet.data
            data=bytes(data_ptr[:data_len])
            scapy_packet=Ether(data)
            scapy_packet.time= (header.ts_sec + header.ts_usec / 1000000.0) - start_time
            procces_packet(scapy_packet)
            """
            print(event)
            contador+=1
            print("---------------------------------")
            print(contador)
            print(time.time()-start_time)
            print(event)
            print(sni.empty())"""
            sni.free_packet(packet_ptr)

def valid_option(config,section,option,fallback,valid_values):
    value=config.get(section,option,fallback=fallback)
    if value not in valid_values:
        raise ValueError(f"'{option}' must be one of {valid_values}, providied '{value}'")
    return value

def finish(signum,frame):
    event.set()
    os.system('clear')
    print('Procesing the last packets...')
    while not cipher_event.is_set():
        time.sleep(0.1)
        continue

def match_regular_expression_size(size):
    if size is None:
        return 0
    regex = r'^(\d+(\.\d+)?)([KMG])$'
    match=re.match(regex, size)
    if match:
        str_size, _, unit = match.groups()
        size=float(str_size)
        units = {'K': 1024, 'M': 1024**2, 'G': 1024**3}
        bytes=int(size*units[unit])
        return bytes
    else:
        raise argparse.ArgumentTypeError(f"Invalid size: {size}. Examples (5K, 8.9M, 100.25G).")
    
def match_regular_expression_time(time):
    if time is None:
        return 0
    regex = r"(\d+)([DHMS])"
    matches = re.findall(regex, time)
    total_time = 0
    for match in matches:
        str_time, unit = match
        int_time = int(str_time)
        units = {'D': 86400, 'H': 3600, 'M': 60, 'S': 1}
        total_time += int_time * units[unit]
    if total_time == 0:
        raise argparse.ArgumentTypeError(f"Invalid time: {time}. Examples (5D, 2H, 30M, 100S, 4D20M).")
    return total_time

def sniffing():
    iface=interface.encode("utf-8")
    bpf_filter=filter_bpf.encode("utf-8")
    sni.start_capture(iface,bpf_filter,timeout,total_packages,total_lenght)

def configure_c():
    sni.empty.restype=ctypes.c_int
    sni.dequeue.restype = ctypes.POINTER(Packet)
    sni.free_packet.argtypes=[ctypes.POINTER(Packet)]
    sni.start_capture.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_int,ctypes.c_int]

list_protocols=["IP","IPv6","MAC"]

list_send=["WEB","DISK","FTP","S3","WEBDAV","SFTP","SCP"]

def validate_protocols(protocols):
    lista = protocols.split(",") if protocols else []
    if set(lista).issubset(list_protocols):
        return lista
    else:
        argparse.ArgumentTypeError(f"Protocols must be a combination of {', '.join(list_protocols)}")

def validate_send(send):
    lista=send.split(",")
    if set(lista).issubset(list_send):
        return lista
    else:
        argparse.ArgumentTypeError(f"Send must be a combination of {', '.join(list_send)}")

def print_help_file():
    help_file = "help.txt"  # Nombre del archivo de ayuda
    if os.path.exists(help_file):
        with open(help_file, "r") as file:
            print(file.read())
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.format_help = print_help_file
    args = parser.parse_args()
    config=configparser.ConfigParser()
    sni=ctypes.CDLL("./liba.so")
    configure_c()
    try:
        config.read('config.ini')
        mode=valid_option(config,'General','Mode','map',list(anon.keys()))
        header_ptr=valid_option(config,'General','Header','none',list(headers.keys()))
        interface=valid_option(config,'General','Interface','eth0',get_if_list())
        macmode=valid_option(config,'General','MacMode','map',list(Mac_modes.modesMac.keys()))
        ipv6mode=valid_option(config,'General','IPv6Mode','map',list(IPv6_modes.modes6.keys()))
        timeout=match_regular_expression_time(config.get('General','Timeout',fallback=None))
        total_packages=config.getint('General','TotalPackages',fallback=0)
        total_lenght=match_regular_expression_size(config.get('General','TotalLenght',fallback=None))
        packages_pcap=config.getint('General','PackagesPcap',fallback=0)
        rotate=match_regular_expression_time(config.get('General','RotateTime',fallback=None))
        filter_bpf=config.get('General','BPF',fallback="")
        size=match_regular_expression_size(config.get('General','Size',fallback=None))
        protocols=validate_protocols(config.get('General','Protocols',fallback=None))
        cipher=valid_option(config,'General','Cipher',"none",list(ciphers_modes.keys()))
        if "GPG"== cipher:
            gpgkey=config.get('General','GPGKey')
            with open(gpgkey, 'rb') as pubkey:
                public_key=RSA.import_key(pubkey.read())
        if "ZIP"== cipher:
            zipkey=config.get('General','ZipKey',fallback="Secreto")
        hashipv4=config.get('General','HashIpv4',fallback='Secreto')
        location=validate_send(config.get('General','Protocols',fallback="DISK"))
        stats_thread = threading.Thread(target=stadistics, daemon=True)
        #stats_thread.start() #TODO al final de todo cambiar de orden el stats_thread y el sniff para que si hay un error en el filtro salte
        worker = threading.Thread(target=packet_thread, daemon=True)
        worker.start()
        rotate_thread= threading.Thread(target=rotation, daemon=True)
        rotate_thread.start()
        sniffing()
        finish(None,None)
        sni.free_queue()
        #TODO revisar tcp,udp y icmp con ipv6
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sni.free_queue()
        sys.exit(1)
