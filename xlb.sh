#!/bin/bash

./xlb -i eth0 -r ;./xlb -i eth0 -v
./xlb_cmdline -i eth0 -A 10.1.2.1 -t 80 -s 10.0.0.27 -d 10.0.0.24 -m 52:54:00:11:00:18 
./xlb_cmdline -i eth0 -A 10.1.2.1 -t 80 -s 10.0.0.27 -d 10.0.0.23 -m 52:54:00:11:00:17 
./xlb_cmdline -i eth0 -A 10.1.2.1 -t 80 -s 10.0.0.27 -d 10.0.0.22 -m 52:54:00:11:00:16 

./xlb_cmdline -i eth0 -L

