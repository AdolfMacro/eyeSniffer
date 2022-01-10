import socket
from platform import system as osName
from os import system , environ
from time import sleep
from sys import argv
from colorama import Fore as color
from struct import *
from ctypes import *
import binascii
from datetime import datetime
fileList=[]
def chTmpDir():
    if system('cd /tmp/eyeSniffer')==0:
        pass
    else :
        system("mkdir /tmp/eyeSniffer")
def tcp_flags( raw_data): 
    (src_port,dest_port,sequence, acknowledgment, offset_reserved_flags) = unpack( '! H H L L H', raw_data[:14]) 
    offset = (offset_reserved_flags >> 12) * 4 
    flag_urg = (offset_reserved_flags & 32) >> 5 
    flag_ack = (offset_reserved_flags & 16) >> 4 
    flag_psh = (offset_reserved_flags & 8) >> 3 
    flag_rst = (offset_reserved_flags & 4) >> 2 
    flag_syn = (offset_reserved_flags & 2) >> 1 
    flag_fin = offset_reserved_flags & 1 
    data = raw_data[offset:] 
    flags={
        'FIN' : flag_fin,
        'SYN' : flag_syn,
        'RST' : flag_rst,
        'PSH' : flag_psh,
        'ACK' : flag_ack,
        'URG' : flag_urg,
    }
    if flag_ack:
        return flags,acknowledgment
    else:
        return flags,0
def help():
    print("""python 
Help :
    python3 main.py [ip version] [network protocol(tcp , udp , icmp)] [host]
    -dB [addrs]    -> Addresses that are blocked by default
    -fN            -> Filter contentless packages(udp and tcp)
    -fi            -> Block suspicious packets (For example attacker flood identical packets)
    -sh [commands] -> Block if the following shell commands were in the packets
    
    --help         -> This page
Examples :
    python3 main.py 4 tcp 127.0.0.1 -dB 192.168.1.179,127.0.0.53 -fN -fi -sh ping,sudo
    _.-* Be careful to put ',' between them when entering quantities such as -dB or -sh, and do not put white spaces between inputs.*-._

    """)
def clear():
    if 'linux' in osName().lower():
        system("clear")
    elif 'windows' in osName().lower():
        system("cls")
    else:
        system("clear")
def typer(string,printed,time):
    lastString=printed+'\n'
    for i in string:
        print(lastString)
        lastString+=i
        if not i ==' ':
            sleep(time)
        clear()
    print(lastString)
def polity(packet,addr,defaultBlocks,fNonePacks,fSusPacks,shellFilters):
    if defaultBlocks:
        defaultBlocks=defaultBlocks.split(',')
        for ip in defaultBlocks:
            try:
                ipFile=open(f'/tmp/eyeSniffer/{ip}','r')
                lines=ipFile.read().splitlines()
                if 'Blocked' in lines:
                    return
            except FileNotFoundError:
                pass
            # if not system(f'sudo iptables -I INPUT -s {ip} -j DROP'): ------------------------------------------------------------------------------------------------------------------------------------------------------
            print(f"\n[*]IP {ip} successfully blocked...")
            # else :
            #     print(f"We were not able to successfully block the ip address, please check if the 'iptables' tool is installed or not\n then check the argvs for more information about argvs run tool with --help")
            with open(f"/tmp/eyeSniffer/{ip}",'w')as f:
                f.write("Blocked")
                break
    try:    
        chd=0        
        if not packet['data_size'] or packet['data_size']<0:
            ipFile=open(f'/tmp/eyeSniffer/{addr[0]}','r')
            lines=ipFile.read().splitlines()
            if 'Blocked' in lines or 'Blocked\n' in lines:
                return
            for line in lines:
                if line.strip():
                    itms=line.split(',')
                    #FIN 7 , SYN 8 , RST 9 , PSH 10 , ACK 11 , URG 12
                    lastLine=lines[lines.index(line)].strip()
                    if int(itms[6])<=0 and lastLine.split(',')==itms:
                        chd+=1
                    else :
                        break
                    if chd==100:
                        # if not system(f'sudo iptables -I INPUT -s {ip} -j DROP'):-----------------------------------------------------------------------------------------------------------------------------------------------------
                        print(f"\n[*]IP {addr[0]} successfully blocked , ...")
                        with open(f"/tmp/eyeSniffer/{addr[0]}",'w')as f:
                            f.write("Blocked")
                        break
                        # else :
                        #     print(f"We were not able to successfully block the ip address, please check if the 'iptables' tool is installed or not\n then check the argvs for more information about argvs run tool with --help")                            

            if packet['protocol']=='6' or packet['protocol']=='17':
                pass
    except TypeError:
        return

def main():
    # readConfig()
    prtcls=['tcp','icmp','udp']    
    eye=f"""
                ___________
            .-=d88888888888b=-.
        .:d8888pr"|\|/-\|'rq8888b.
      ,:d8888P^//\-\/_\ /_\/^q888/b.
    ,;d88888/~-/ .-~  _~-. |/-q88888b,
   //8888887-\ _/    ({color.RED}卐{color.RESET}) \\\-\/Y88888b\\
   \8888888|// T      `    Y _/|888888 o
    \q88888|- \l           !\_/|88888p/
     'q8888l\-//\         / /\|!8888P'
       'q888\/-| "-,___.-^\/-\/888P'
         `=88\./-/|/ |-/!\/-!/88='
            ^^"-------------"^  

        """
    
    try:
        if '--help' in argv:
            help()
            exit()
        ipV=argv[1]
        if not (ipV=='4' or ipV=='' or ipV=='6'):
            print(f"\n\n{color.RED}Error The entered values are incorrect (eyeSniffrt --help)...{color.RESET}")
            exit()
        prtcl=argv[2].lower()
        if not prtcl in prtcls:
            print(f"\n\n{color.RED}Error The entered values are incorrect (eyeSniffrt --help)...{color.RESET}")
            exit()
        host=argv[3]
        if not prtcl in prtcls:
            print(f"\n\n{color.RED}Error The entered values are incorrect (eyeSniffrt --help)...{color.RESET}")
            exit()
        
    except IndexError:
        print("Try with --help ...")
        exit()
    typer("\tWelcome to eye packet sniffer",eye,0.1)
    if ipV=='6':
        socketIPv=socket.AF_INET6
    elif ipV=='4':
        socketIPv=socket.AF_INET
    if prtcl=='tcp':
        socketPrtcl=socket.IPPROTO_TCP
    elif prtcl=='udp':
        socketPrtcl=socket.IPPROTO_UDP
    elif prtcl=='icmp':
        if socketIPv==socket.AF_INET:
            socketPrtcl=socket.IPPROTO_ICMP
        if socketIPv==socket.AF_INET6:
            socketPrtcl=socket.IPPROTO_ICMPV6
    s = socket.socket(socketIPv, socket.SOCK_RAW, socketPrtcl)
    s.bind((host,0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    argvs=['-dB','-fN','-fi','-sh']
    index=4
    defaultBlocks=''
    fNonePacks=False
    fSusPacks=False
    shellFilters=''
    for arg in argv[3:] :
        if arg in argvs:
            if arg==argvs[0]:
                defaultBlocks=argv[index+1]
            elif arg==argvs[1]:
                fNonePacks=True
            elif arg==argvs[2]:
                fSusPacks=True
            elif arg==argvs[3]:
                shellFilters=argv[index+2]
            index+=1
        elif not arg in argvs:
            if argv[index-1] in argvs:
                pass
            elif not index<=4 :
                print(f"{color.RED}ValueError , try with --help ...{color.RESET}")
    while 1:
        try:
            if defaultBlocks:
                polity(None,None, defaultBlocks, None, None, None)
            packet,addr= s.recvfrom(65565)
            ip_header= packet[0:20]
            iph= unpack('!BBHHHBBH4s4s' , ip_header)
            version_ihl= iph[0]
            version= version_ihl >> 4
            ihl= version_ihl & 0xF
            iph_length= ihl * 4
            ttl= iph[5]
            protocol= iph[6]
            s_addr= socket.inet_ntoa(iph[8])
            d_addr= socket.inet_ntoa(iph[9])
            eth_length = 14
            if prtcl=='tcp':
                
                unpackFormat="!HHLLBBHHH"
                start=0
                end=20
                header = packet[start:end]
                protoh = unpack(unpackFormat , header)
                tcph_length = protoh[4] >> 4
                h_size = eth_length + iph_length + tcph_length * 4
                source_port = protoh[0]
                dest_port = protoh[1]
                length = protoh[2]
                checksum = protoh[3]
            elif prtcl=='udp':
                unpackFormat="!HHHH"
                start=0
                end=8
                header = packet[start:end]
                protoh = unpack(unpackFormat , header)
                h_size = eth_length + iph_length + 8
                source_port = protoh[0]
                dest_port = protoh[1]
                length = protoh[2]
                checksum = protoh[3]
            else:
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]
                header = unpack('!BBH' , icmp_header)
                type = header[0]
                code = header[1]
                checksum = header[2]
                icmph_length = 4
                h_size = eth_length + iph_length + icmph_length
                data = packet[h_size:]
            flags,ack_num=tcp_flags(packet)
            if prtcl=='tcp' or prtcl=='udp':
                packetD={
                'dst':addr[0],
                'version':str(version),
                'version-ihl':str(version_ihl),
                'ttl':str(ttl),
                'protocol':str(protocol),
                'srcAddr':str(s_addr),
                'dstAddr':str(d_addr),
                'data' : packet[h_size:],
                'data_size' : len(packet) - h_size,
                'dstPort' : str(dest_port),
                'srcPort' : str(source_port),
                'protoH' : str(protoh),
                'chSum' : str(checksum)
            }
            else :
                packetD={
                'dst':addr[0],
                'version':str(version),
                'version-ihl':str(version_ihl),
                'ttl':str(ttl),
                'protocol':str(protocol),
                'srcAddr':str(s_addr),
                'dstAddr':str(d_addr),
                'data' : packet[h_size:],
                'data_size' : len(packet) - h_size,
                'chSum' : str(checksum)}
            chTmpDir()
            ip_file=open(f'/tmp/eyeSniffer/{str(addr[0])}','a')
            ip_fileR=open(f'/tmp/eyeSniffer/{str(addr[0])}','r')
            lines=ip_fileR.read().splitlines()
            if not 'Blocked' in lines:
                write=f'\n{prtcl},{str(ihl)},{str(ttl)},{str(protocol)},{str(s_addr)},{str(d_addr)},{len(packetD["data"])}'
                if prtcl=='tcp':
                    packetD['flags']=flags
                    strFlags=''
                    for itm in packetD["flags"].values():
                        strFlags+=(','+str(itm))
                    write+=f'{strFlags},{ack_num}'
                write+=","+str(str(datetime.now()).split(' ')[1].split(":")[1])
                ip_file.write(write)
                if len(lines)>100 :
                    polity(packetD,addr, defaultBlocks, fNonePacks, fSusPacks, shellFilters)
        except KeyboardInterrupt:
            if input("\nExit [N,y]? ").lower()=='y':
                exit()
            else:
                pass
main()