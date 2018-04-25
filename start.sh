#!/bin/sh

insmod driver/net_traffic_drv.ko

./app/bin/net_traffic_app -d
