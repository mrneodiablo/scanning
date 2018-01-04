# -*- coding: utf-8 -*-

"""
Trong phần này mình sẽ scan snmp để lấy thông tin cơ bản của server về parse ra đồng thời brute force snmp nếu port open
, tương tự như scan tcp

thông tin
- SNMP: UDP port 161
- SNMP Version 1, 2c, v3
- SNMP Authen: community
- SNMP HEADER

|========================================================================================|
|              [version]: 1/2/v2c/3                                                      |
|----------------------------------------------------------------------------------------|
|              [community]:  pass                                                        |
|----------------------------------------------------------------------------------------|
| [pdu type] | request id | error-status| error-index| Name  | Value | Name | Value | .. |
|========================================================================================|

 [pdu_type] :    - Get :     0xa0
               - GetNext : 0xa1
               - Response : 0xa2
               - Set:       0xa3
 [request id] : là id của request gởi tới agent vào được respone = với ID đó
 [error-status] : noError(0), tooBig(1), noSuchName(2), badValue(3), readOnly(4), genErr(5)
 [error-index] : số thứ tự của OID có lỗi (nếu có). 
 [Name]: tên OID
 [Value] : value                   
"""
import argparse
from scapy.all import *
import threading
import signal

# list community default for scann
from scapy.layers.inet import IP, UDP
from scapy.layers.snmp import SNMP, SNMPnext, SNMPvarbind, SNMPresponse, ASN1F_SNMP_PDU_RESPONSE

default_communities = ['public', 'mtopjcsea', '0']

# default_communities = ['public', 'mtopjcsea', '0', '0392a0', '1234', '2read', '3com', '3Com', '3COM', '4changes', 'access', 'adm', 'admin', 'Admin', 'administrator', 'agent', 'agent_steal', 'all', 'all private', 'all public', 'anycom', 'ANYCOM', 'apc', 'bintec', 'blue', 'boss', 'c', 'C0de',
#                        'cable-d',
#                        'cable_docsispublic@es0', 'cacti', 'canon_admin', 'cascade', 'cc', 'changeme', 'cisco', 'CISCO', 'cmaker', 'comcomcom', 'community', 'core', 'CR52401', 'crest', 'debug', 'default', 'demo', 'dilbert', 'enable', 'entry', 'field', 'field-service', 'freekevin', 'friend', 'fubar',
#                        'guest', 'hello', 'hideit', 'host', 'hp_admin', 'ibm', 'IBM', 'ilmi', 'ILMI', 'intel', 'Intel', 'intermec', 'Intermec', 'internal', 'internet', 'ios', 'isdn', 'l2', 'l3', 'lan', 'liteon', 'login', 'logon', 'lucenttech', 'lucenttech1', 'lucenttech2', 'manager', 'master',
#                        'microsoft', 'mngr', 'mngt', 'monitor', 'mrtg', 'nagios', 'net', 'netman', 'network', 'nobody', 'NoGaH$@!', 'none', 'notsopublic', 'nt', 'ntopia', 'openview', 'operator', 'OrigEquipMfr', 'ourCommStr', 'pass', 'passcode', 'password', 'PASSWORD', 'pr1v4t3', 'pr1vat3', 'private',
#                        ' private', 'private ', 'Private', 'PRIVATE', 'private@es0', 'Private@es0', 'private@es1', 'Private@es1', 'proxy', 'publ1c', 'public', ' public', 'public ', 'Public', 'PUBLIC', 'public@es0', 'public@es1', 'public/RO', 'read', 'read-only', 'readwrite', 'read-write', 'red',
#                        'regional', '<removed>', 'rmon', 'rmon_admin', 'ro', 'root', 'router', 'rw', 'rwa', 'sanfran', 'san-fran', 'scotty', 'secret', 'Secret', 'SECRET', 'Secret C0de', 'security', 'Security', 'SECURITY', 'seri', 'server', 'snmp', 'SNMP', 'snmpd', 'snmptrap', 'snmp-Trap',
#                        'SNMP_trap', 'SNMPv1/v2c', 'SNMPv2c', 'solaris', 'solarwinds', 'sun', 'SUN', 'superuser', 'supervisor', 'support', 'switch', 'Switch', 'SWITCH', 'sysadm', 'sysop', 'Sysop', 'system', 'System', 'SYSTEM', 'tech', 'telnet', 'TENmanUFactOryPOWER', 'test', 'TEST', 'test2',
#                        'tiv0li', 'tivoli', 'topsecret', 'traffic', 'trap', 'user', 'vterm1', 'watch', 'watchit', 'windows', 'windowsnt', 'workstation', 'world', 'write', 'writeit', 'xyzzy', 'yellow', 'ILMI']


q = Queue.Queue()
#===================================================================#
# default OID global                                                #
#===================================================================#
# RouteOIDS = {
#     'ROUTDESTOID': [".1.3.6.1.2.1.4.21.1.1", "Destination"],
#     'ROUTHOPOID': [".1.3.6.1.2.1.4.21.1.7", "Next Hop"],
#     'ROUTMASKOID': [".1.3.6.1.2.1.4.21.1.11", "Mask"],
#     'ROUTMETOID': [".1.3.6.1.2.1.4.21.1.3", "Metric"],
#     'ROUTINTOID': [".1.3.6.1.2.1.4.21.1.2", "Interface"],
#     'ROUTTYPOID': [".1.3.6.1.2.1.4.21.1.8", "Route type"],
#     'ROUTPROTOID': [".1.3.6.1.2.1.4.21.1.9", "Route protocol"],
#     'ROUTAGEOID': [".1.3.6.1.2.1.4.21.1.10", "Route age"]
# }
#
# InterfaceOIDS = {
#     # Interface Info
#     'INTLISTOID': [".1.3.6.1.2.1.2.2.1.2", "Interfaces"],
#     'INTIPLISTOID': [".1.3.6.1.2.1.4.20.1.1", "IP address"],
#     'INTIPMASKOID': [".1.3.6.1.2.1.4.20.1.3", "Subnet mask"],
#     'INTSTATUSLISTOID': [".1.3.6.1.2.1.2.2.1.8", "Status"]
# }
#
# ARPOIDS = {
#     # Arp table
#     'ARPADDR': [".1.3.6.1.2.1.3.1 ", "ARP address method A"],
#     'ARPADDR2': [".1.3.6.1.2.1.3.1 ", "ARP address method B"]
# }

OIDS = {
    'SYSTEM': ["1.3.6.1.2.1.1.1", "SYSTEM Info"]
}

#
# WINDOWS_OIDS = {
#     'RUNNING PROCESSES': ["1.3.6.1.2.1.25.4.2.1.2", "Running Processes"],
#     'INSTALLED SOFTWARE': ["1.3.6.1.2.1.25.6.3.1.2", "Installed Software"],
#     'SYSTEM INFO': ["1.3.6.1.2.1.1", "System Info"],
#     'HOSTNAME': ["1.3.6.1.2.1.1.5", "Hostname"],
#     'DOMAIN': ["1.3.6.1.4.1.77.1.4.1", "Domain"],
#     'USERS': ["1.3.6.1.4.1.77.1.2.25", "Users"],
#     'UPTIME': ["1.3.6.1.2.1.1.3", "UpTime"],
#     'SHARES': ["1.3.6.1.4.1.77.1.2.27", "Shares"],
#     'DISKS': ["1.3.6.1.2.1.25.2.3.1.3", "Disks"],
#     'SERVICES': ["1.3.6.1.4.1.77.1.2.3.1.1", "Services"],
#     'LISTENING TCP PORTS': ["1.3.6.1.2.1.6.13.1.3.0.0.0.0", "Listening TCP Ports"],
#     'LISTENING UDP PORTS': ["1.3.6.1.2.1.7.5.1.2.0.0.0.0", "Listening UDP Ports"]
# }
#
# LINUX_OIDS = {
#     'RUNNING PROCESSES': ["1.3.6.1.2.1.25.4.2.1.2", "Running Processes"],
#     'SYSTEM INFO': ["1.3.6.1.2.1.1", "System Info"],
#     'HOSTNAME': ["1.3.6.1.2.1.1.5", "Hostname"],
#     'UPTIME': ["1.3.6.1.2.1.1.3", "UpTime"],
#     'MOUNTPOINTS': ["1.3.6.1.2.1.25.2.3.1.3", "MountPoints"],
#     'RUNNING SOFTWARE PATHS': ["1.3.6.1.2.1.25.4.2.1.4", "Running Software Paths"],
#     'LISTENING UDP PORTS': ["1.3.6.1.2.1.7.5.1.2.0.0.0.0", "Listening UDP Ports"],
#     'LISTENING TCP PORTS': ["1.3.6.1.2.1.6.13.1.3.0.0.0.0", "Listening TCP Ports"]
# }
#
# CISCO_OIDS = {
#     'LAST TERMINAL USERS': ["1.3.6.1.4.1.9.9.43.1.1.6.1.8", "Last Terminal User"],
#     'INTERFACES': ["1.3.6.1.2.1.2.2.1.2", "Interfaces"],
#     'SYSTEM INFO': ["1.3.6.1.2.1.1.1", "System Info"],
#     'HOSTNAME': ["1.3.6.1.2.1.1.5", "Hostname"],
#     'SNMP Communities': ["1.3.6.1.6.3.12.1.3.1.4", "Communities"],
#     'UPTIME': ["1.3.6.1.2.1.1.3", "UpTime"],
#     'IP ADDRESSES': ["1.3.6.1.2.1.4.20.1.1", "IP Addresses"],
#     'INTERFACE DESCRIPTIONS': ["1.3.6.1.2.1.31.1.1.1.18", "Interface Descriptions"],
#     'HARDWARE': ["1.3.6.1.2.1.47.1.1.1.1.2", "Hardware"],
#     'TACACS SERVER': ["1.3.6.1.4.1.9.2.1.5", "TACACS Server"],
#     'LOG MESSAGES': ["1.3.6.1.4.1.9.9.41.1.2.3.1.5", "Log Messages"],
#     'PROCESSES': ["1.3.6.1.4.1.9.9.109.1.2.1.1.2", "Processes"],
#     'SNMP TRAP SERVER': ["1.3.6.1.6.3.12.1.2.1.7", "SNMP Trap Server"]
# }

#==========================END DEFINE OID=====================================

def banner(hav=True):
    if hav:
        print """
        "##################################"
        "   _____ _   ____  _______        "
        "  / ___// | / /  |/  / __ \       "
        "  \\__ \\/  |/ / /|_/ / /_/       "
        " ___/ / /|  / /  / / ____/        "
        "/____/_/ |_/_/  /_/_/             "
        "                                  "
        "SNMP Scanner & Enumeration Script "
        "##################################"
 ##################################################       
        """

class SNMPError(Exception):
    """
    wrapper của Exceptoin
    """
    pass

class SNMPVersion():
    v1 = 0
    v2c = 1
    v3 = 2

    @classmethod
    def iversion(cls, v):
        if v in ['1', 'v1']:
            return cls.v1
        elif v in ['2', 'v2', 'v2c']:
            return  cls.v2c
        elif v in ['3', 'v3']:
            return  cls.v3
        raise ValueError('No such version %s' % v)

    @classmethod
    def sversion(cls, v):
        if not v:
            return 'v1'
        elif v == 1:
            return 'v2c'
        elif v == 2:
            return 'v3'
        raise ValueError('No such version number %s' % v)


###########################################################
# parse input ip
def ipRange(ip):
    """
    "192.168.1.1-192.168.1.255"
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

def ipList(list_ip):
    """
    
    :param list_ip: 192.168.6.200,13.228.20.244
    :return: ["192.168.6.200" ,"13.228.20.244"]
    """
    ip_range = []
    if len(str(list_ip).strip(" ").split(",")) > 1:
        for x in str(list_ip).strip(" ").split(","):
            ip_range.append(x)

    return ip_range

def read_file_dic(fi):

    if not os.path.exists(fi):
        print "file " + str(fi) + " không tồn tại"
        sys.exit(1)

    with open(str(fi), "r") as f:
        list_com = f.readlines()
    f.close()
    return list_com

def worker_scan(dic, version, timeout):
    ip = q.get()
    output = ""
    for com in dic:
        try:
            ans, unans = sr(IP(dst=ip) / UDP(sport=RandShort(), dport=161) / SNMP(community=str(com), version=str(version), PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1"))])), timeout=float(timeout), verbose=0)
            # check unrespone
            # for u in unans:
            #     print com

            # check respone
            for send_ans, reci_ans in ans:
                if str(reci_ans.getlayer("SNMP")[SNMPresponse].error.val) == "0":
                    output = ip + ": " + "[" + com + "]" + " - " + str(reci_ans.getlayer("SNMP")[SNMPresponse][SNMPvarbind].value.val)
                    print output
                    sys.exit(0)

        except:
            continue


if __name__ == '__main__':

    # show banner
    banner()

    # parse param
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--ip", help="lựa chọn IP để scan", default=None)
    parse.add_argument("-li", "--list_ip", help="lựa chọn IP để scan", default=None)
    parse.add_argument("-f", "--file", help="chon file dict community", default=None)
    parse.add_argument("-t", "--timeout", help="chọn thời gian timeout cho mỗi community", default=1)
    parse.add_argument("-v", "--version", help="chọn version của SNMP", default="v2c")
    args = parse.parse_args()



    if args.file != None:
        default_communities = read_file_dic(args.file)

    if args.ip != None:
        list_ip = ipRange(str(args.ip))

    if args.list_ip != None:
        list_ip = ipList(str(args.list_ip))

    if args.ip == None and args.list_ip == None:
        print "thêm ip"
        sys.exit(1)

    time_out = args.timeout
    version = args.version


    # start main

    NUMBER_THERAD = len(list_ip)
    threads = []

    # put ip in queue
    for ip in list_ip:
        q.put(str(ip))


    try:
        for x in range(NUMBER_THERAD):
            w = threading.Thread(target=worker_scan, args=(default_communities, version, time_out))
            w.setDaemon(True)
            threads.append(w)
            w.start()


        for t in threads:
            t.join()

    except (KeyboardInterrupt) :
        print "Ctrl+C  Exit.."
        sys.exit(1)


    print "[#] Scan done at.. " + time.strftime("%Y-%m-%d %H:%M:%s")