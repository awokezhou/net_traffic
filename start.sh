#!/bin/sh

insmod driver/net_traffic.ko

./app/bin/net_traffic_app -d
