#ifndef __NT_NETLINK_H__
#define __NT_NETLINK_H__


int nt_netlink_send(int type, char *data, int len);
void nt_netlink_recv(struct sk_buff *skb);
void nt_netlink_exit(void);
int nt_netlink_init(void);



#endif /* __NT_NETLINK_H__ */
