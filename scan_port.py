# -*- coding: utf-8 -*-
"""
Trong Phần này chúng ta sẽ sử dụng cơ chế sync scan port của victim để biết đang mở port nào
sử sụng TCP layer 4 dest port , dest IP,
== > return syn+ack okie
== > return rst not open
"""

import threading
import Queue
from scapy.all import *
import argparse
import threading
import datetime

from scapy.layers.inet import TCP, IP, ICMP, UDP

src_port = RandShort()

q = Queue.Queue()


class bcolors():
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Flags():
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


def checkICMP(ip):
    conf.verb = 0

    try:
        ping = sr1(IP(dst=ip)/ICMP()/"hello", timeout=1)
        if ping != None:
            result =  bcolors.OKGREEN + "\n[*] Target up, Beginning Scan .." + ip + bcolors.ENDC
        else:
            print  bcolors.FAIL + "\n[!] Couldn't Resolve Target " + ip + bcolors.ENDC
            print bcolors.FAIL + "[!] Exiting .." + bcolors.ENDC
            sys.exit(1)
    except Exception:
        print  "[!] Exiting .."
        sys.exit(1)

    return result

def tcp_conn(ip, port):
    """
    Đã tiến hành bắt tay 3 bước
    
    :param ip: 192.168.1.1
    :param port: 80
    :return: string data for show
    """
    src_port = RandShort()
    result= sr1(IP(dst=str(ip)) / TCP(dport=int(port), sport=src_port), timeout=0.1, retry=1, verbose=0)
    try:
        if result == None:
            output =  bcolors.FAIL + str(port) + " tcp blocked" + bcolors.ENDC
        elif result[TCP] and result[TCP].flags != 20:
            output = bcolors.OKBLUE + str(port) + " tcp opened" + bcolors.ENDC
        else:
            output = bcolors.FAIL + str(port) + " tcp closed" + bcolors.ENDC
    except Exception as e:
        print e
        output = bcolors.FAIL + str(port) +" tcp blocked" + bcolors.ENDC

    return output

def tcp_syn(ip, port):
    """
        SYN        --->
open    <---   SYN+ACK
        RST        ---->
        
        SYN      ---->
close   <------  RST
block   no respone
       
       
    chỉ gởi gói syn, và rst liền
    :param ip: 
    :param port: 
    :return: 
    """
    src_port = RandShort()
    ans, unans = sr(IP(dst=str(ip)) / TCP(dport=int(port), sport=src_port, flags="S"), timeout=1, verbose=0)

    output = ""
    # check firewall no respine
    for s in unans:
        output =  bcolors.FAIL + str(port) + " tcp blocked" + bcolors.ENDC

    # check respone
    for send_ans, reci_ans in ans:

        # có cờ syn trong gói respone
        if reci_ans.haslayer(TCP) and reci_ans.getlayer(TCP).flags & Flags.SYN:
            send(IP(dst=str(ip)) / TCP(dport=int(port), sport=src_port, flags="R"), verbose=0)
            output = bcolors.OKBLUE + str(port) + " tcp opened" + bcolors.ENDC

        # có cờ reset in TCP respone
        if reci_ans.haslayer(TCP) and reci_ans.getlayer(TCP).flags & Flags.RST:
            output = bcolors.FAIL + str(port) + " tcp closed" + bcolors.ENDC

        # nếu có gói echo replay type 3 code trong hinh thì firewall
        if reci_ans.haslayer(ICMP) and int(reci_ans.getlayer(ICMP).type) == 3 and int(reci_ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            output = bcolors.FAIL + str(port) + " tcp blocked" + bcolors.ENDC


    return output

def tcp_fin(ip, port):
    """
        FIN -->
close   <--- RST
open    no respone    
filter  <---- ICMP
    gởi FIN nếu mở no respone, đóng RST
    :param ip: 
    :param port: 
    :return: 
    """
    src_port = RandShort()
    ans, unans = sr(IP(dst=str(ip)) / TCP(dport=int(port), sport=src_port, flags="F"), timeout=0.5, verbose=0)

    output = ""

    # khong respone
    for send_unans in unans:
        output = bcolors.WARNING + str(port) + " tcp opened|block" + bcolors.ENDC

    # co respone, respone RST
    for rq , rs in ans:

        #respone RST
        if rs.haslayer(TCP) and rs.getlayer(TCP).flags & Flags.RST:
            output = bcolors.FAIL + str(port) + " tcp closed" + bcolors.ENDC

        # nếu có gói echo replay type 3 code trong hinh thì firewall
        if rs.haslayer(ICMP) and int(rs.getlayer(ICMP).type) == 3 and int(rs.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            output = bcolors.FAIL + str(port) + " tcp blocked" + bcolors.ENDC
    return output

def tcp_ack(ip, port):
    """
    
         ACK --->
close    <---  RST
block    no respone

    Tấn công ACK chủ yếu đê phát hiện firewall, 
    sent ack có firewall statefull, 
    respone rst không có firewall, 
    chỉ hoạt động trên unix
    :param ip: 
    :param port: 
    :return: 
    """
    src_port = RandShort()
    ans, unans = sr(IP(dst=str(ip)) / TCP(dport=int(port), sport=src_port, flags="A"), timeout=0.1, retry=1, verbose=0)

    output = ""
    # check firewall
    for s in unans:
        output = bcolors.FAIL + str(port) + " tcp stateful firewall " + bcolors.ENDC

    # check respone
    for send_ans, reci_ans in ans:

        # respone rst
        if reci_ans.haslayer(TCP) and reci_ans.getlayer(TCP).flags & Flags.RST:
            output = bcolors.OKBLUE + str(port) + " tcp no firewall" + bcolors.ENDC

        # nếu có gói echo replay type 3 code trong hinh thì firewall
        if reci_ans.haslayer(ICMP) and int(reci_ans.getlayer(ICMP).type) == 3 and int(reci_ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            output = bcolors.FAIL + str(port) + " tcp stateful firewall " + bcolors.ENDC

    return output

def tcp_null(ip, port):
    """
              null flags -->
block/open    no respone
close         <--------- RST
block         <------- ICMP      
    là phương pháp quét nâng cao với tất cả cờ được tắt, có thể vượt qua firewall
    no respone mở,
    rst đóng
    :param ip: 
    :param port: 
    :return: 
    """

    src_port = RandShort()
    ans, unans = sr(IP(dst=str(ip)) / TCP(dport=int(port), sport=src_port, flags=""), timeout=0.1, retry=1, verbose=0)

    output = ""
    # check firewall
    for s in unans:
        output = bcolors.WARNING + str(port) + " tcp opened|blocked " + bcolors.ENDC

    # check respone
    for send_ans, reci_ans in ans:

        # respone rst
        if reci_ans.haslayer(TCP) and reci_ans.getlayer(TCP).flags & Flags.RST:
            output = bcolors.FAIL + str(port) + " tcp closed " + bcolors.ENDC

        # nếu có gói echo replay type 3 code trong hinh thì firewall
        if reci_ans.haslayer(ICMP) and int(reci_ans.getlayer(ICMP).type) == 3 and int(reci_ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            output = bcolors.FAIL + str(port) + " tcp block " + bcolors.ENDC

    return output

def tcp_windown(ip, port):
    """
        ACK ----> 
close    <---- windown size = 0
open     <---- windown size > 0
block    no respone
block    <--- ICMP          
    Dựa vào windown size để phát hiện
    :param ip: 
    :param port: 
    :return: 
    """
    src_port = RandShort()
    ans, unans = sr(IP(dst=str(ip)) / TCP(dport=int(port), sport=src_port, flags="A"), timeout=0.1, retry=1, verbose=0)

    output = ""
    # check firewall
    for s in unans:
        output = bcolors.FAIL + str(port) + " tcp blocked " + bcolors.ENDC

    # check respone
    for send_ans, reci_ans in ans:

        # respone rst
        if reci_ans.haslayer(TCP) and int(reci_ans.getlayer(TCP).window) == 0:
            output = bcolors.FAIL + str(port) + " tcp closed " + bcolors.ENDC

        if reci_ans.haslayer(TCP) and int(reci_ans.getlayer(TCP).window) > 0:
            output = bcolors.OKBLUE + str(port) + " tcp opened " + bcolors.ENDC

        # nếu có gói echo replay type 3 code trong hinh thì firewall
        if reci_ans.haslayer(ICMP) and int(reci_ans.getlayer(ICMP).type) == 3 and int(reci_ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            output = bcolors.FAIL + str(port) + " tcp block " + bcolors.ENDC
    return output

def udp_conn(ip, port):
    """
    no respone open
    return icmp type 3 code 3 error
    :param ip: 
    :param port: 
    :return: string data
    """
    src_port = RandShort()
    ans, unans = sr(IP(dst=str(ip)) / UDP(dport=int(port)), timeout=1, retry=1, verbose=0)

    output = ""
    # check firewall
    for s in unans:
        output = bcolors.WARNING + str(port) + " udp opened| blocked " + bcolors.ENDC

    # check respone
    for send_ans, reci_ans in ans:
        # nếu có gói echo replay type 3 code trong hinh thì firewall
        if reci_ans.haslayer(ICMP) and int(reci_ans.getlayer(ICMP).type) == 3 and int(reci_ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            output = bcolors.FAIL + str(port) + " tcp block " + bcolors.ENDC
    return output

def workerScanning(type=None, ping=False):
    """
    
    :param type: TCP_CON, TCP_SYN, TCP_FIN, TCP_ACK, TCP_NULL, TCP_WINDOWN, UDP_CON
    :param ping: 
    :return: 
    """
    # to_do_job = {"ip": ip, "list_port": list_port}
    to_do_job = q.get()
    data = ""

    if ping == True:
        ping = checkICMP(to_do_job["ip"])
        data = data + ping + "\n"
    else:
        data = data + bcolors.OKGREEN + "\n[*] Target up, Beginning Scan .." + to_do_job["ip"] + "\n" + bcolors.ENDC

    if type == "TCP_CON":
        data = data + bcolors.HEADER + "SCAN TCP CONNECT" + bcolors.ENDC + "\n"
        for port in to_do_job["list_port"]:
            sc = tcp_conn(to_do_job["ip"],port)
            data = data + str(sc) + "\n"
        q.task_done()
    elif type == "TCP_SYN":
        data = data + bcolors.HEADER + "SCAN TCP SYN" + bcolors.ENDC + "\n"
        for port in to_do_job["list_port"]:
            sc = tcp_syn(to_do_job["ip"], port)
            data = data + str(sc) + "\n"
        q.task_done()
    elif type == "TCP_FIN":
        data = data + bcolors.HEADER + "SCAN TCP FIN" + bcolors.ENDC + "\n"
        for port in to_do_job["list_port"]:
            sc = tcp_fin(to_do_job["ip"], port)
            data = data + str(sc) + "\n"
        q.task_done()
    elif type == "TCP_ACK":
        data = data + bcolors.HEADER + "SCAN TCP ACK" + bcolors.ENDC + "\n"
        for port in to_do_job["list_port"]:
            sc = tcp_ack(to_do_job["ip"], port)
            data = data + str(sc) + "\n"
        q.task_done()
    elif type == "TCP_NULL":
        data = data + bcolors.HEADER + "SCAN TCP NUL" + bcolors.ENDC + "\n"
        for port in to_do_job["list_port"]:
            sc = tcp_null(to_do_job["ip"], port)
            data = data + str(sc) + "\n"
        q.task_done()
    elif type == "TCP_WINDOWN":
        data = data + bcolors.HEADER + "SCAN TCP WINDOWN" + bcolors.ENDC + "\n"
        for port in to_do_job["list_port"]:
            sc = tcp_windown(to_do_job["ip"], port)
            data = data + str(sc) + "\n"
        q.task_done()
    elif type == "UDP_CON":
        data = data + bcolors.HEADER + "SCAN UDP" + bcolors.ENDC + "\n"
        for port in to_do_job["list_port"]:
            sc = udp_conn(to_do_job["ip"], port)
            data = data + str(sc) + "\n"
        q.task_done()
    else:
        print "TYPE wrong"
    print data

def createJobScanning(list_ip, list_port):
    """
    đẩy các job scanning in queue để worker get job to run
     
     Mỗi IP là 1 job và sẽ chạy tuần tự các port
    :return: 
    """
    for ip in list_ip:
        q.put({"ip": ip, "list_port": list_port})
    #q.join()

def ipRange(ip):
    """
    
    :param start_ip: 
    :param end_ip: 
    :return:  ["192.168.1.1","192.168.1.2"]
    """
    if len(str(ip).strip(" ").split("-")) > 1:
        start_ip = str(ip).strip(" ").split("-")[0]
        end_ip = str(ip).strip(" ").split("-")[1]
    else:
        start_ip = str(ip).strip(" ").split("-")[0]
        end_ip = str(ip).strip(" ").split("-")[0]

    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range

def portRange(port):
    """
    input: 
    :param port: 
    :return:
     ["60", "61"]
    """
    # 60-90
    # 60,70,90
    # 60
    parse_port = []
    tmp = str(port).strip(" ").split(",")
    for p in tmp:
        if "-" in p:
            parse_port.extend([x for x in xrange(int(p.split("-")[0]), 1+int(p.split("-")[1]))])
        else:
            parse_port.append(p)

    return parse_port

if __name__ == '__main__':

    parse = argparse.ArgumentParser()
    parse.add_argument("--type", help="lựa chọn loại scan TCP_CON, TCP_SYN, TCP_FIN, TCP_ACK, TCP_NULL, TCP_WINDOWN, UDP_CON", default="TCP_CON")
    parse.add_argument("--ip", help="lựa chọn IP để scan", default="NONE")
    parse.add_argument("--port", help="lựa chọn PORT để scan")
    args = parse.parse_args()

    try:
        type = args.type
        list_ip = ipRange(str(args.ip))
        list_port = portRange(args.port)
    except Exception as e:
        print  e.message
        sys.exit(1)

    NUMBER_THERAD = len(list_ip)
    threads = []

    try:
        createJobScanning(list_ip, list_port)
        for x in range(NUMBER_THERAD):
            w = threading.Thread(target=workerScanning, args=(type, False))
            w.setDaemon(True)
            threads.append(w)
            w.start()
        for t in threads:
            t.join()

        print bcolors.HEADER + "[#] Scan done at.. " + time.strftime("%Y-%m-%d %H:%M:%s") + bcolors.ENDC
    except KeyboardInterrupt:
       raise


