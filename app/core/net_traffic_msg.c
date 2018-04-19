#include <linux/netlink.h>


#include "nt_msg.h"





int group_mask(int group)
{
    return (1 << group);
}

nt_ret nt_msg_netlink_send(uint32_t knl_fd, 
                                   uint16_t knl_typ, 
                                   char *msg_data, 
                                   uint32_t data_len)
{
    int msg_len;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nlh;
    
    if(msg_data && (data_len > NT_MSG_KNL_PAYLOAD_LEN))
    {
        nt_err("invalid message msgDataLen:%d", data_len);
        return nt_err_param;
    } 

    memset((void*)&iov, 0 ,sizeof(iov));
    memset((void*)&msg, 0, sizeof(msg));        
    msg_len = NLMSG_SPACE(data_len);
        
    nlh = (struct nlmsghdr *)nt_mem_alloc_z(msg_len);
    if (!nlh)
    {
        nt_err("malloc mem error");
        return nt_err_nomem;
    }

    memset(nlh, 0, msg_len);
    nlh->nlmsg_len = msg_len;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_type = knl_typ;
    nlh->nlmsg_flags = 0;

    if (data_len)
    {
        memcpy(NLMSG_DATA(nlh), msg_data, data_len);
    }
    
    iov.iov_base = (void*)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(knl_fd, &msg, 0) < 0)
    {
        nt_err("sendmsg error");
        nt_mem_free(nlh);
        return nt_err_sock_send;
    }

    nt_mem_free(nlh);
    return nt_ok;;
}

nt_ret nt_msg_netlink_init(uint16_t knl_typ, 
                                   uint32_t knl_grp, 
                                   uint32_t *fd)
{
    int rt;
    int knl_fd;
    struct sockaddr_nl addr;
    nt_ret ret = nt_ok;

    memset((void*)&addr, 0, sizeof(addr));

    knl_fd = web_socket_create(PF_NETLINK, SOCK_RAW, knl_typ);
    if (knl_fd < 0)
    {
        nt_err("netlink socket create error");
        return nt_err_sock_creat;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = group_mask(knl_grp);

    rt = bind(knl_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rt < 0)
    {
        nt_err("netlink socket bind error");
        close(knl_fd);
        return nt_err_sock_bind;
    }

    /*send pid to kernel*/
    ret = nt_msg_netlink_send(knl_fd, 0, NULL, 0);
    if (nt_ok != ret)
    {
        nt_err("netlink socket send to kernel error");
        close(knl_fd);
        return nt_err_sock_send;
    }

    return ret;
}

nt_ret nt_msg_knl_register(uint32_t type, uint32_t group, nt_run_mgr *mgr)
{
    nt_ret ret = nt_ok;
    
    nt_msg_knl *msg;
    nt_msg_knl *check;

    /* Before to add a new msg, lets make sure it's not a duplicated */
    nt_list_for_each_entry(check, &mgr->msg_knl_list, _head) {
        if (check->kn_typ == type &&
            check->kn_grp == group) {
            nt_warn("duplicated %d:%d, skip.",
                    type, group);
            return nt_err_exist;
        }
    }

    msg = nt_mem_alloc_z(sizeof(nt_msg_knl));
    if (nt_unlikely(!msg)) {
        nt_err("alloc listen failed");
        return nt_err_nomem;
    }

    msg->knl_typ = type;
    msg->knl_grp = group;

    ret = nt_msg_netlink_init(msg->knl_typ,
                              msg->knl_grp,
                              &msg->knl_fd);
    if (nt_ok != ret)
    {
        nt_err("netlink init error, ret %d", ret);
        nt_mem_free(msg);
        return ret;
    }

    nt_list_append(&msg->_head, &mgr->msg_knl_list);

    return nt_ok;
}

nt_ret nt_msg_init(nt_run_mgr *mgr)
{
    nt_msg_knl_register(NT_MSG_KNL_NET_TRAFFIC, 
                        0,
                        mgr);

    return nt_ok;
}
