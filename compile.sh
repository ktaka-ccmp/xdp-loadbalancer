#!/bin/bash

gcc -c -o icmp.o icmp.c
gcc -c -o mac.o mac.c
gcc -c -o route.o route.c
gcc -c -o rmi.o rmi.c
gcc -o rmi rmi.o icmp.o mac.o route.o

