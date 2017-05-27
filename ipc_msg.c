#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/un.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "ipc_msg.h"

#define IPC_LOG_PATH  "/tmp/ipc_log.disk"
#define DEBUG
#ifndef DEBUG
#define IPC_DEBUG(fmt,args...) do{}while(0)
#else
#define IPC_DEBUG(fmt,args...) do{console_printf("[IPC:%05d]:"fmt, __LINE__, ##args);}while(0)
#endif
#define IPC_ERROR(fmt,args...) do{ \
	ipc_log(IPC_LOG_PATH, "[IPC:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)


void console_printf(const char *fmt, ...)
{
	FILE *fp = NULL;
	va_list ap;

	fp = fopen("/dev/console", "w");
	if (fp) {
		va_start(ap, fmt);
		vfprintf(fp, fmt, ap);
		va_end(ap);
		fclose(fp);
	}
}

void ipc_log_bak(char *file)
{
	FILE *fp = NULL;
	char cmdline[1024] = {0,};

	fp = fopen(file, "rb");
	if (fp == NULL)
		return;

	fseek(fp, 0, SEEK_END);
	if (ftell(fp) > 50*1024) {
		fclose(fp);
		memset(cmdline, 0, sizeof(cmdline));
		snprintf(cmdline, sizeof(cmdline) - 1,\
		"mv %s %s.bak", file, file);
		system(cmdline);
	} else {
		fclose(fp);
	}
}

void ipc_log(char *file, const char *fmt, ...)
{
	FILE *fp = NULL;
	va_list ap;

	ipc_log_bak(file);

	fp = fopen(file, "a+");
	if (fp == NULL)
		return;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fclose(fp);
}

int ipc_write(int fd, char *buf, int len)
{
	int wlen = 0, ylen = 0, offset = 0;

	if ((!buf) || (len <= 0)) {
		IPC_ERROR("data err\n");
		return -1;
	}

	wlen = len;
	while((ylen = write(fd, &buf[offset], wlen)) != wlen) {
		if(ylen > 0) {
			offset += ylen;
			wlen -= ylen;
		} else {
			IPC_ERROR("ylen:%d, errno:%d, err:%s\n", ylen, errno, strerror(errno));
			return -1;
		}
	}
	return 0;
}

int ipc_read(int fd, char *buf, int len)
{
	int rlen = 0, ylen = 0, offset = 0;

	if ((!buf) || (len <= 0)){
		IPC_ERROR("data err\n");
		return -1;
	}

	rlen = len;
	while ((ylen = read(fd, &buf[offset], rlen)) != rlen) {
		if(ylen > 0) {
			offset += ylen;
			rlen -= ylen;
		} else {
			IPC_ERROR("ylen:%d, errno:%d, err:%s\n", ylen, errno, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int ipc_setsock(int sock, int time)
{
	struct timeval timeout;

	timeout.tv_sec = time;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		IPC_ERROR("rcvtimeo fail, %m\n");
		return -1;
	}
	return 0;
}

int ipc_data_push(struct ipc_header *msg, int *offset, void *data, int len)
{
	if ((!msg) || (!offset) || (!data)) {
		IPC_ERROR("data err\n");
		return -1;
	}

	if (*offset >= msg->len || \
			(len + *offset) > msg->len) {
		IPC_ERROR("data wrong:%d, %d, %d\n", *offset, msg->len, len);
		return -1;
	}

	memcpy(IPC_DATA(msg) + *offset, data, len);
	(*offset) += len;
	return 0;
}

int ipc_data_pop(struct ipc_header *msg, int *offset, void *data, int len)
{
	if ((!msg) || (!offset) || (!data)) {
		IPC_ERROR("data err\n");
		return -1;
	}

	if (*offset >= msg->len || \
			(len + *offset) > msg->len) {
		IPC_ERROR("data wrong:%d, %d, %d\n", *offset, msg->len, len);
		return -1;
	}

	memcpy(data, IPC_DATA(msg) + *offset, len);
	(*offset) += len;
	return 0;
}
int ipc_nonblock_client_init(char *path, int nsec)
{
	int error=0,  flag, res;
	fd_set rset, wset;
	struct timeval tv;
	int sock = 0, len = 0;
	socklen_t elen;
	struct sockaddr_un addr;

	if ((!path) || (!strlen(path))) {
		printf("path is err\n");
		return -1;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("create socket fail, errno:%d, %s\n", errno, strerror(errno));
		return -1;
	}

	memset (&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
	len = sizeof(addr.sun_family) + sizeof(addr.sun_path);

	flag = fcntl(sock, F_GETFL, 0);
	if(flag < 0){
		printf("fcntl get failed\n");
		return -1;
	}
	if(fcntl(sock, F_SETFL, flag | O_NONBLOCK) < 0){
		printf("fcntl set failed\n");
		return -1;
	}
	res = connect(sock, (struct sockaddr *)&addr, len);
	if(res < 0){
		if(errno != EINPROGRESS){
			printf("connect error:%s\n", strerror(errno));
			return -1;
		}
	}else if(res == 0){
		goto ok;
	}

	FD_ZERO(&rset);
	FD_SET(sock, &rset);
	wset = rset;
	tv.tv_sec = nsec;
	tv.tv_usec = 0;

	res = select(sock+1, &rset, &wset, NULL, nsec ? &tv:NULL);
	if(res < 0){
		printf("select failed\n");
		return -1;
	}else if(res == 0){
		printf("Nonblock connect timeout!!\n");
		return -1;
	}
	
	if(FD_ISSET(sock, &rset) || FD_ISSET(sock, &wset)){
		elen = sizeof(error);
		if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &elen) < 0){
			printf("getsockopt failed\n");
			return -1;
		}
		if(error){
			return -1;
		}else{
			goto ok;
		}
	}else{
		printf("connect read and write, connect failed!!!\n");
		return -1;
	}

ok:
	if(fcntl(sock, F_SETFL, flag) < 0){
		printf("fcntl set failed\n");
		return -1;
	}
	printf("Noblock Connect Successful->%d\n", sock);	
	return sock;
}
//ipc client
int ipc_client_init(char *path)
{
	int sock = 0, len = 0, ret = 0;
	struct sockaddr_un addr;

	if ((!path) || (!strlen(path))) {
		IPC_ERROR("path is err\n");
		return -1;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		IPC_ERROR("create socket fail, errno:%d, %s\n", errno, strerror(errno));
		return -1;
	}
	/*Set socket timeout to 120s*/
	ipc_setsock(sock, 120);

	memset (&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
	len = sizeof(addr.sun_family) + sizeof(addr.sun_path);

	
	printf("IPC Connect Begin-->tims=%ld\n", time(NULL));
	ret = connect(sock, (struct sockaddr *)&addr, len);
	printf("IPC Connect End-->tims=%ld\n", time(NULL));
	if (ret < 0) {
		close(sock);
		printf("connect error:%d, path:%s\n", ret, path);
		return -1;
	} else {
		printf("connect OK,socket=%d\n", sock);
	}
	return sock;
}

int ipc_only_send(char *path, int msg, void *send_buf, int send_len)
{
	struct ipc_header *hdr;
	int ret = IPC_RET_ERR, sock = 0;
	int offset = 0;

	if ((!path) || (!strlen(path))) {
		IPC_ERROR("path is err\n");
		return ret;
	}

	if (!send_buf)
		send_len = 0;

	sock = ipc_client_init(path);
	if (sock < 0)
		return ret;

	hdr = (struct ipc_header *)malloc(IPC_TOTAL_LEN(send_len));
	if (hdr == NULL) {
		IPC_ERROR("malloc fail\n");
		goto err;
	}

	hdr->msg = msg;
	hdr->len = send_len;
	hdr->direction.flag = IPCF_ONLY_SEND;

	if (send_buf && (send_len > 0) && \
			(ipc_data_push(hdr, &offset, send_buf, send_len) < 0)) {
		goto err;
	}
	if (ipc_write(sock, (char *)hdr, IPC_TOTAL_LEN(send_len)) < 0) {
		IPC_ERROR("write hdr err\n");
		goto err;
	}
	ret = 0;
err:
	if (hdr)
		free(hdr);
	close(sock);
	return ret;
}

int ipc_send(char *path, int msg, void *send_buf, int send_len, void *recv_buf, int recv_len)
{
	struct ipc_header *hdr;
	int ret = IPC_RET_ERR, sock = 0;
	int offset = 0;

	if ((!path) || (!strlen(path))) {
		IPC_ERROR("path is err\n");
		return ret;
	}

	if (!send_buf)
		send_len = 0;
	if (!recv_buf)
		recv_len = 0;

	sock = ipc_client_init(path);
	if (sock < 0)
		return ret;

	ipc_setsock(sock, 3);

	hdr = (struct ipc_header *)malloc(IPC_TOTAL_LEN(send_len));
	if (hdr == NULL) {
		IPC_ERROR("malloc fail\n");
		goto err;
	}

	hdr->msg = msg;
	hdr->len = send_len;
	hdr->direction.flag = IPCF_NORMAL;

	if (send_buf && (send_len > 0) && \
			(ipc_data_push(hdr, &offset, send_buf, send_len) < 0)) {
		goto err;
	}

	if (ipc_write(sock, (char *)hdr, IPC_TOTAL_LEN(send_len)) < 0) {
		IPC_ERROR("write hdr err\n");
		goto err;
	}

	free(hdr);
	hdr = NULL;

	hdr = (struct ipc_header *)malloc(IPC_TOTAL_LEN(0));
	if (hdr == NULL) {
		IPC_ERROR("malloc fail\n");
		goto err;
	}
	memset(hdr, 0, IPC_TOTAL_LEN(0));

	if (ipc_read(sock, (char *)hdr, IPC_TOTAL_LEN(0)) < 0) {
		IPC_ERROR("read hdr err, 0x%X, %d\n", msg, send_len);
		goto err;
	}

	if (recv_buf && (recv_len > 0) && \
			(ipc_read(sock,recv_buf, recv_len) < 0)) {
		goto err;
	}

	ret = hdr->direction.response;
err:
	if (hdr)
		free(hdr);
	close(sock);
	return ret;
}

static void sig_hander(int signo)
{
	IPC_ERROR("recv signal, signal number = %d\n", signo);
	exit(0);
}

int ipc_server_init(char *path)
{
	int len = 0, sock = 0;
	sigset_t sig;
	struct sockaddr_un addr;

	if ((!path))
		return IPC_RET_ERR;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		IPC_ERROR("create socket fail, errno:%d, %s\n", errno, strerror(errno));
		return IPC_RET_ERR;
	}

	unlink(path);
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);

	if (bind(sock, (struct sockaddr *)&addr, len) < 0) {
		IPC_ERROR("bind socket fail, errno:%d, %s\n", errno, strerror(errno));
		close(sock);
		return IPC_RET_ERR;
	}

	if (listen(sock, 5) < 0) {
		IPC_ERROR("listen on socket fail, errno:%d, %s\n", errno, strerror(errno));
		close(sock);
		return IPC_RET_ERR;
	}

	sigemptyset(&sig);
	/*sigaddset(&sig, SIGALRM);*/
	sigaddset(&sig, SIGABRT);
	sigaddset(&sig, SIGPIPE);
	sigaddset(&sig, SIGQUIT);
	/*sigaddset(&sig, SIGTERM);*/
	sigaddset(&sig, SIGUSR1);
	sigaddset(&sig, SIGUSR2);
	sigprocmask(SIG_BLOCK, &sig, NULL);
	signal(SIGBUS, sig_hander);
	signal(SIGHUP, sig_hander);
	signal(SIGILL, sig_hander);

	IPC_DEBUG("ipc server success, path:%s, sock:%d\n", path, sock);

	return sock;
}

