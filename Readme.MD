# SCAN

Trong phần này mình sẻ có các script đơn lẻ để scan port của server

```
Sử dụng thư việc scapy và pcap trên linux
```

## scan_port.py 

scan port TCP. Có các cơ chế scan khác nhau, syn, fin, windown .. Mỗi cơ chế để có chú thích rõ trong script


## scan_snmp_server.py

Scan protocol snmp theo list server , nếu port open brute force community string theo dic để lấy thông tin