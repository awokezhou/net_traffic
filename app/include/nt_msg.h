#ifndef __NT_MSG_H__
#define __NT_MSG_H__



#define NT_MSG_KNL_NET_TRAFFIC      29

#define NT_MSG_KNL_PAYLOAD_LEN     128

typedef struct _nt_msg_knl{
    uint32_t knl_fd;
    uint16_t knl_typ;
    uint32_t knl_grp;
    nt_list _head;
} nt_msg_knl;





#endif /* __NT_MSG_H__ */
