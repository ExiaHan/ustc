#!/bin/bash

dmesg --clear
rm /var/capture_info
make clean
make
rmmod nssniffer
insmod nssniffer.ko
dmesg | tail
