#ifndef __IPC_COMM_H__
#define __IPC_COMM_H__

#include <stdio.h>

struct ipc_header {
	int msg;
	int len;
	union {
		int flag; //use for send user assign send type
		int response; //use for send to request for response
	}direction;
};
enum {
	IPCF_NORMAL = 0,
	IPCF_ONLY_SEND,
};


#define IPC_RET_ERR   -110
#define IPC_HEADER_LEN   (sizeof(struct ipc_header))
#define IPC_TOTAL_LEN(len)   (len + IPC_HEADER_LEN)
#define IPC_DATA(msg)   ((void*)(((char*)msg) + IPC_TOTAL_LEN(0)))

extern int ipc_data_push(struct ipc_header *msg, int *offset, void *data, int len);
extern int ipc_data_pop(struct ipc_header *msg, int *offset, void *data, int len);
extern int ipc_only_send(char *path, int msg, void *send_buf, int send_len);
extern int ipc_send(char *path, int msg, void *send_buf, int send_len, void *recv_buf, int recv_len);
extern int ipc_server_init(char *path);
int ipc_client_init(char *path);
extern int ipc_server_close(char *path);
int ipc_read(int fd, char *buf, int len);
int ipc_write(int fd, char *buf, int len);
int ipc_nonblock_client_init(char *path, int nsec);

#endif //__IPC_COMM_H__
