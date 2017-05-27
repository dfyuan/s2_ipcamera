#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <poll.h>
#include <pthread.h>


#include "file_mod.h"
#include "av_mod.h"
#include "log.h"
#include "ipc_msg.h"

#define IPC_PATH_CMERA "/tmp/ipc_path_camera"


static int daemonize(void)
{
	int pid, i;

	switch(fork()){
		/* fork error */
		case -1:
			exit(1);

		/* child process */
		case 0:
		/* obtain a new process group */
			if((pid = setsid()) < 0) {
				exit(1);
			}

			/* close all descriptors */
			for (i = getdtablesize(); i >= 0; --i) 
			close(i);

			i = open("/dev/null", O_RDWR); /* open stdin */
			dup(i); /* stdout */
			dup(i); /* stderr */

			umask(000);

			return 0;

		/* parent process */
		default:
			exit(0);
	}

	return 1;
}

static int handler_sig(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigfillset(&act.sa_mask);
	if ((sigaction(SIGCHLD, &act, NULL) == -1) ||
		(sigaction(SIGTERM, &act, NULL) == -1) ||
		(sigaction(SIGSEGV, &act, NULL) == -1)) {
		DEBUG("Fail to sigaction[Errmsg:%s]\r\n", strerror(errno));	
	}

	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1) {		
		DEBUG("Fail to signal(SIGPIPE)[Errmsg:%s]\r\n", strerror(errno));	
	}
	return 0;
}

int main(int argc, char **argv)
{
	fd_set fds;
	int ipc_fd;
	struct timeval tv;
	socklen_t len = 0;
	struct sockaddr addr;
	int read_sock = 0, ret;	
	struct ipc_header hdr, *phdr, *reply_phdr;
	void *resbuf = NULL;
	int reslen;


	if(access("/etc/config/ipcamera", F_OK)){
		DEBUG("Not Start Progress\n");
		exit(1);
	}
	if(argc <= 1){
		daemonize();
		handler_sig();
	}

	av_mod_init();
	file_mod_init(0);
	ipc_fd = ipc_server_init(IPC_PATH_CMERA);

	for (;;) {
		FD_ZERO(&fds);
		FD_SET(ipc_fd, &fds);

		memset(&tv, 0, sizeof(tv));
		tv.tv_sec = 2;		
		if (select(ipc_fd + 1, &fds, NULL, NULL, &tv) <= 0) {
			continue;			
		}

		if (!FD_ISSET(ipc_fd, &fds)){
			continue;
		}
		read_sock = accept(ipc_fd, &addr, &len);
		if(read_sock < 0) {
			DEBUG("accept fail, sock:%d[%s]\n", ipc_fd, strerror(errno));
			continue;
		}
		
		memset(&hdr, 0, sizeof(hdr));
		if(ipc_read(read_sock, (char *)&hdr, sizeof(hdr)) < 0) {
			DEBUG("read header err\n");
			close(read_sock);
			continue;
		}
		phdr = (struct ipc_header *)malloc(IPC_TOTAL_LEN(hdr.len));
		if (phdr == NULL) {
			DEBUG("malloc fail\n");
			close(read_sock);
			continue;
		}
		
		memcpy(phdr, &hdr, IPC_HEADER_LEN);
		if ((phdr->len > 0) && \
				(ipc_read(read_sock, (char *)IPC_DATA(phdr), phdr->len) < 0)) {
			free(phdr); 		
			close(read_sock);
			DEBUG("read body err\n");
			continue;
		}		
		DEBUG("Read IPC Data: Command->%d Payload->%d\n", phdr->msg, phdr->len);
		reslen = 0;
		resbuf	= NULL;
		if(phdr->msg == 1){			
			DEBUG("Set Username Function:%d\n", phdr->msg);
			struct ipcam_info *cameraInfo = (struct ipcam_info *)IPC_DATA(phdr);
			ret = av_mod_setinfo(cameraInfo->username, cameraInfo->password, cameraInfo->uid);;
		}else if(phdr->msg == 2){
			DEBUG("Get Camera Information Function:%d\n", phdr->msg);
			resbuf = calloc(1, sizeof(struct ipcam_info));
			reslen = sizeof(struct ipcam_info);
			av_mod_status((struct ipcam_info *)resbuf);
		}else{
			DEBUG("Unknow Module %d\n", phdr->msg);
			free(phdr);
			close(read_sock);
			continue;
		}
		if (hdr.direction.flag == IPCF_ONLY_SEND) {
			DEBUG("Disk Handle %d Finish IPCF_ONLY_SEND\n", phdr->msg);
			free(phdr);
			close(read_sock);
			continue;
		}
		
		reply_phdr = (struct ipc_header *)malloc(IPC_TOTAL_LEN(reslen));
		if (reply_phdr == NULL) {
			DEBUG("malloc fail\n");
			free(phdr); 		
			close(read_sock);
			continue;
		}
		memset(reply_phdr, 0, IPC_TOTAL_LEN(reslen));
		reply_phdr->msg = phdr->msg;
		reply_phdr->direction.response= ret;//response result
		reply_phdr->len = reslen;
		/*Free header memory*/
		free(phdr);
		
		if (reply_phdr->len) {
			memcpy(IPC_DATA(reply_phdr), resbuf, reslen);
			free(resbuf);
			resbuf = NULL;
		}
		
		if(ipc_write(read_sock, (char *)reply_phdr, IPC_TOTAL_LEN(reply_phdr->len)) < 0) {
			DEBUG("write header err, 0x%X, %d\n", hdr.msg, hdr.len);
		}

		free(reply_phdr);
		close(read_sock);
	}
	
	return 0;
}
