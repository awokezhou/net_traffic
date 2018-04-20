# net_traffic
get network flows from linux netfilter, analyze flows's characteristics, then classification them by neural network

## 简介
传统的网络流量识别分类方法，如基于Port的流量分类、基于IP的流量分类、基于固定内容的分类等方式，由于应用App的快速扩展、协议加密等原因，不能较好的对网络流量进行准确的分类。本项目参考剑桥大学Andrew W.Moore等人的“nprobe”课题，基于Linux系统和神经网络算法，研究网络流量的分类，提高流量分类的准确率。

## 目录
项目包括driver、app、doc、reference、anaylze目录

driver：Linux内核钩子，在网络数据流经的INPUT、FORWARD、OUTPUT等链上截获报文，发送到应用层

app：实现数据包到流的转化，主要是分析TCP流，初步得到流的基本特性

anaylze：python脚本，使用神经网络算法对流进行训练和分类
