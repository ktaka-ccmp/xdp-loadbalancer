# XDP Loadbalancer

## To load xdp bytecode

Load:
```
./xlb -i eth0 -v
```

Unload:
```
./xlb -i eth0 -r
```

Check to see the xdp binary is loaded
```
# ip link show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 52:54:00:11:00:1b brd ff:ff:ff:ff:ff:ff
    prog/xdp id 94 tag e09d47c63a72ab36 jited 
```
The line, "prog/xdp id 94 tag e09d47c63a72ab36 jited" indicate that the xdp byte code is correctly hooked to the eth0.

## Setup loadbalancer

Basic usage of the xlb_cmdline
```
Usage: ./xlb_cmdline [...]
    -i Interface name(eg. eth0)
    -A ServiceIP(a.k.a. VIP)
    -t (for TCP, optional, default)
    -u (for UDP, optional)
    -r WorkerIP
    -v verbose
    -L list lb table
    -l list lbcache
    -h Display this help
```

Create service
```
./xlb_cmdline -i eth0 -A 10.1.4.1 -p 80
```

Add real servers
```
./xlb_cmdline -i eth0 -a 10.1.4.1 -p 80 -r 10.0.0.24
./xlb_cmdline -i eth0 -a 10.1.4.1 -p 80 -r 10.0.0.23
./xlb_cmdline -i eth0 -a 10.1.4.1 -p 80 -r 10.0.0.22
```

Show registered services.
```
./xlb_cmdline -i eth0 -L
service: 10.1.4.1:80(6) {
src: 10.0.0.27, dst: 10.0.0.22 (52:54:0:11:0:16)
src: 10.0.0.27, dst: 10.0.0.23 (52:54:0:11:0:17)
src: 10.0.0.27, dst: 10.0.0.24 (52:54:0:11:0:18)
}
```

Delete real servers
```
./xlb_cmdline -i eth0 -d 10.1.4.1 -p 80 -r 10.0.0.22
./xlb_cmdline -i eth0 -d 10.1.4.1 -p 80 -r 10.0.0.23
./xlb_cmdline -i eth0 -d 10.1.4.1 -p 80 -r 10.0.0.24
```

Delete service
```
./xlb_cmdline -i eth0 -D 10.1.4.1 -p 80
```


