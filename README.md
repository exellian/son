# son
Simple proxy tool for windows and linux based on libuv 

## Example:

### double redirect udp traffic for GMOD server:

Public Server:
./son.out udp4:0.0.0.0:27015 udp6:[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:27015
Home Server:
./son.out udp6:[::0]:27015 udp4:10.0.1.50:27015

## Documentation
Use the following commands to rewrite packets:

A rewrite command has the following format:

    protocol:address:port protocol:address:port

protocol:

    tcp          Uses tcp on both ipv6 and ipv4
    udp          Uses udp on both ipv6 and ipv4
    tcp4         Uses tcp on ipv4
    tcp6         Uses tcp on ipv6
    udp4         Uses udp on ipv4
    udp6         Uses udp on ipv6

address (optional) (default value: 0.0.0.0 and [::0]):

    127.0.0.1    Ipv4 format example
    [::1]        Ipv6 format example

port:

    8080         Port example
