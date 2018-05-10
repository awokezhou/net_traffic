## 概述
本文是net_traffic driver的设计文档，所有有关内核中的处理都在此处进行了说明

driver在本项目中至关重要，是研究网络流量的数据最终来源，driver负责获取在设备上接收和发送的网络数据流，经过一些处理和组织，形成易于上层应用接收和分析的数据结构。当然，在linux系统中，要获取网络数据流量的方式有多种，例如使用RAW_SOCKET绑定具体协议，或者经由专门的抓包软件如tcmdump将数据获取上来，应用程序直接拿来用，为什么没有选择这些看起来更加便捷的方式呢？有以下几方面的考虑：

1. 专有的抓包程序或者RAW_SOCKET方式获取的数据，并不易于本项目的app进行分析，仍然要进行额外的处理
2. 这些方式似乎不能够抓取到所有的数据包，而本项目需要尽可能抓取到数据包的全貌
3. 实时性考虑

## 整体架构
下图是driver主要做的几件事情，获取数据包->暂存->构建结构->发送到应用层，这里暂存和构建结构几乎是同一件事情，后文会提到。
![](https://github.com/awokezhou/net_traffic/blob/master/doc/nt_drv_02.png)

由于本项目是在虚拟机上运行，不可能从网卡驱动中获取最新的skb，并且考虑到方便过滤需要的协议(主要是TCP报文)，在数据包的获取部分，采用的是hook函数

skb在driver中的暂存和结构构建，这里使用的主要数据结构是fifo，将获取的数据简易化处理后，pull到fifo中，另外设计一个fifo的管理结构，用于记录fifo大小、当前已经pull的skb数量等信息。采用这样的数据结构，很大程度上是因为内核态与用户态通信方式的限制

最后是将数据发送到应用层程序，因为在内核态环境比较复杂，而在用户态代码的运行环境较为纯净，所有的操作都在可控范围，因此选择在用户态去进行数据的分析工工作而不是在内核态做分析。另一个重要的原因是内核不支持复杂的运算操作如除法，有很多的不便利性。由于项目是运行于虚拟机上，而不是实际的linux设备，netlink无法创建，并且普通的文件系统难以创建和维护，这里采用了proc文件系统+mmap的方式来处理

## get skb
如下图，是网络数据在linux协议栈中流经的几个点，driver获取网络数据流量的核心在于在其中两个点上注册了hook函数，一个是PRE_ROUTING，另一个是POST_ROUTING。这两个点保证了所有访问本机的数据、从本机发出的数据以及在本机进行转发的数据，都可以完全接收到
![](https://github.com/awokezhou/net_traffic/blob/master/doc/nt_drv_01.png)

hook函数接收到的数据是sk_buff类型的skb包，即一个以太网数帧。该结构比较庞大，且其中含有很多额外指针域，由于无法直接将该结构发送到应用层，这里需要对它进行简化

简化的主要方向可以参考另外一篇文章《有效的TCP流特性》，这里主要是按照该文章的思想来进行简化的，需要的skb信息主要有服务器端口号、syn标志、psh标志、是否是TCP分组、TCP初始协商窗口、数据包大小

## 暂存和结构
从skb转化为简易报文，采用了net_pkt_t结构，
```c
typedef struct _net_pkt_t {

    uint16_t f_cs:1,
             f_psh:1,
             f_segm:1,
             f_syn:1,
             f_ack;

    uint16_t port;
    uint16_t window;
    uint8_t ip_pkt_median;

    int segm_len;
    int ip_len;
    int eth_len;
    
} net_pkt_t;
```
各种标志很好获得，只要通过调用tcp_hdr(skb)即可获取tcp头信息，这里要注意的是port、window需要调用ntohs()进行字节序转化

用于管理和暂存所有报文的fifo如下图所示
![](https://github.com/awokezhou/net_traffic/blob/master/doc/nt_drv_03.png)

模块在加载时，就调用kmalloc()以页为单位分配一个内存块，并将头部划分为fifo管理结构，其后是多个pkt的暂存区，新到来的pkt放到空的区域，当所有暂存区都被沾满，则清空暂存区，更新fifo管理结构

fifo管理结构
```c
typedef struct {

    uint32_t fifo_size;
    uint32_t fifo_pull;

    net_pkt_t *fifo_base;
    net_pkt_t *fifo_curr;
    
} net_fifo_ctl;
```
其中fifo_size记录整个fifo能够暂存pkt的数目，fifo_pull记录当前已经占用的pkt数目，fifo_base指针指向第一个暂存pkt区的地址，fifo_curr指向当前pull的pkt位置

## 内核态与用户态通信
通信方式采用mmap，用法参照- [The mmap Device Operation](https://github.com/awokezhou/LinuxPage/wiki/The-mmap-Device-Operation)
