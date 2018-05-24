#!/bin/bash

./xlb -i eth0 -r ;./xlb -i eth0 -v
./xlb_cmdline -i eth0 -A 10.1.2.1 -p 80
./xlb_cmdline -i eth0 -a 10.1.2.1 -p 80 -r 10.0.0.24
./xlb_cmdline -i eth0 -a 10.1.2.1 -p 80 -r 10.0.0.23
./xlb_cmdline -i eth0 -a 10.1.2.1 -p 80 -r 10.0.0.22

./xlb_cmdline -i eth0 -L

