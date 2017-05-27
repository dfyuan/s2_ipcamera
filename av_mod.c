#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include "IOTCAPIs.h"
#include "AVAPIs.h"
#include "AVFRAMEINFO.h"
#include "AVIOCTRLDEFs.h"
#include "log.h"
#include "av_mod.h"

#define AV_MOD_CONFIG		"/etc/config/ipconf"
pthread_mutex_t v_lock = PTHREAD_MUTEX_INITIALIZER;
#define VIDEO_BUF_SIZE	128000

enum{
	AV_INIT = 0,
	AV_CONFIG_OK = 1,
	AV_CNT_OK = 2,
};

typedef struct _av_mod_context{
	char username[256];
	char password[256];
	char uid[256];
	int sid;
	int avIndex;
	int status;
	int online;
	pthread_t pid;
}av_mod_context;


av_mod_context	av_modcnt;

static int av_mod_conf_save(av_mod_context *avmod)
{
	int fd;
	char buffer[4096] = {0};

	if(!avmod){
		return -1;
	}
	fd = open(AV_MOD_CONFIG, O_CREAT|O_TRUNC|O_RDWR, 0755);
	if(fd < 0){ 
		close(fd);
		DEBUG("Open %s Failed:%s\n", AV_MOD_CONFIG, strerror(errno));
		return -1;
	}

	snprintf(buffer, sizeof(buffer)-1, "uid=%s\nusername=%s\npassword=%s",
				avmod->uid, avmod->username, avmod->password);

	write(fd, buffer, strlen(buffer));
	close(fd);

	DEBUG("Update %s/%s/%s\n", avmod->uid, avmod->username, avmod->password);

	return 0;
}

static int av_mod_conf_restore(av_mod_context *avmod)
{
	FILE *fp;
	char line[512] = {0}, key[128], value[128];
	int vaild = 0;

	if(!avmod){
		return -1;
	}
	
	fp = fopen(AV_MOD_CONFIG, "r");
	if(fp == NULL){
		DEBUG("Open %s Failed:%s\r\n", 
						AV_MOD_CONFIG, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), fp)) {
		memset(key, 0, sizeof(key));
		memset(value, 0, sizeof(value));		
		if (sscanf(line, "%[^=]=%[^\n ]",
					key, value) != 2)
			continue;
		if(!strcasecmp(key, "username")){
			strcpy(avmod->username, value);
			vaild++;
		}else if(!strcasecmp(key, "password")){
			strcpy(avmod->password, value);	
			vaild++;
		}else if(!strcasecmp(key, "uid")){
			strcpy(avmod->uid, value);
			DEBUG("uid is %s\r\n", avmod->uid);			
			vaild++;
		}
	}
	fclose(fp);
	if(vaild != 3){
		DEBUG("Config May Be Error\n");
		memset(avmod, 0 ,sizeof(av_mod_context));
		return -1;
	}

	return 0;
}


static int av_mod_conncet(av_mod_context *avmod)
{	
	int SID, ret;
	int avIndex, nResend;
	unsigned int srvType;	
	unsigned short val = 0;
	
	char *mode[] = {"P2P", "RLY", "LAN"};
	struct st_SInfo Sinfo;
	int tmpSID = IOTC_Get_SessionID();
	if(tmpSID < 0){
		DEBUG("IOTC_Get_SessionID error code [%d]\n", tmpSID);
		return -1;
	}	

	SID = IOTC_Connect_ByUID_Parallel(avmod->uid, tmpSID);
	DEBUG("IOTC_Connect_ByUID_Parallel, ret=[%d]\n", SID);
	if(SID < 0){
		printf("IOTC_Connect_ByUID_Parallel failed[%d]\n", SID);
		return -1;
	}
	avIndex = avClientStart2(SID, avmod->username, avmod->password, 20, &srvType, 0, &nResend);
	DEBUG("Step 2: call avClientStart2(%d).......\n", avIndex);
	if(avIndex < 0){
		DEBUG("avClientStart2 failed[%d]\n", avIndex);
		goto av_failed;
	}

	if(nResend == 0){
		DEBUG("Resend is not supported.");
	}
	
	memset(&Sinfo, 0, sizeof(struct st_SInfo));	
	if(IOTC_Session_Check(SID, &Sinfo) == IOTC_ER_NoERROR){
		if( isdigit( Sinfo.RemoteIP[0] ))
			DEBUG("Device is from %s:%d[%s] Mode=%s NAT[%d] IOTCVersion[%X]\n",Sinfo.RemoteIP, Sinfo.RemotePort, Sinfo.UID, mode[(int)Sinfo.Mode], Sinfo.NatType, Sinfo.IOTCVersion);
	}
	DEBUG("avClientStart2 OK[%d], Resend[%d]\n", avIndex, nResend);

    avClientCleanBuf(0);

	/*Set ipcamera parameter*/
	ret = avSendIOCtrl(avIndex, IOTYPE_INNER_SND_DATA_DELAY, (char *)&val, sizeof(unsigned short));
	if(ret < 0){
		DEBUG("Send Control IOTYPE_INNER_SND_DATA_DELAY Failed:%d\n", ret);
		goto av_failed;
	}
	DEBUG("send Cmd: IOTYPE_INNER_SND_DATA_DELAY, OK\n");

	SMsgAVIoctrlAVStream ioMsg;
	memset(&ioMsg, 0, sizeof(SMsgAVIoctrlAVStream));
	ret = avSendIOCtrl(avIndex, IOTYPE_USER_IPCAM_START, (char *)&ioMsg, sizeof(SMsgAVIoctrlAVStream));
	if(ret < 0){
		DEBUG("Send Control IOTYPE_USER_IPCAM_START Failed:%d\n", ret);
		goto av_failed;
	}
	DEBUG("send Cmd: IOTYPE_USER_IPCAM_START, OK\n");

	avmod->sid = SID;
	avmod->avIndex = avIndex;
	DEBUG("IPCamera Connect Successful[%d/%d]\n", avmod->sid, avmod->avIndex);
	
	return 0;

av_failed:	
	avClientStop(avIndex);
	DEBUG("avClientStop OK\n");
	IOTC_Session_Close(SID);

	return -1;
}

static int av_mod_recvvideo(int avIndex)
{
	char buf[VIDEO_BUF_SIZE]={0};
	FRAMEINFO_t frameInfo;
	unsigned int frmNo;
	int ret, tmlen;
	int outBufSize = 0;
	int outFrmSize = 0;
	int outFrmInfoSize = 0;

	ret = avRecvFrameData2(avIndex, buf, 
			VIDEO_BUF_SIZE, &outBufSize, &outFrmSize, 
				(char *)&frameInfo, sizeof(FRAMEINFO_t), &outFrmInfoSize, &frmNo);
	
	if(frmNo == 0){
		char *format[] = {"MPEG4","H263","H264","MJPEG","UNKNOWN"};
		int idx = 0;
		if(frameInfo.codec_id == MEDIA_CODEC_VIDEO_MPEG4)
			idx = 0;
		else if(frameInfo.codec_id == MEDIA_CODEC_VIDEO_H263)
			idx = 1;
		else if(frameInfo.codec_id == MEDIA_CODEC_VIDEO_H264)
			idx = 2;
		else if(frameInfo.codec_id == MEDIA_CODEC_VIDEO_MJPEG)
			idx = 3;
		else
			idx = 4;
		DEBUG("--- Video Formate: %s ---\n", format[idx]);
	}

	if(ret == AV_ER_DATA_NOREADY){
	//	DEBUG("AV_ER_DATA_NOREADY[%d]\n", avIndex);
		return 1;
	}else if(ret == AV_ER_LOSED_THIS_FRAME){
		DEBUG("Lost video frame NO[%d]\n", frmNo);
	}else if(ret == AV_ER_INCOMPLETE_FRAME){
		if(outFrmInfoSize > 0)
			DEBUG("Incomplete video frame NO[%d] ReadSize[%d] FrmSize[%d] FrmInfoSize[%u] Codec[%d] Flag[%d]\n", 
					frmNo, outBufSize, outFrmSize, outFrmInfoSize, frameInfo.codec_id, frameInfo.flags);
		else
			DEBUG("Incomplete video frame NO[%d] ReadSize[%d] FrmSize[%d] FrmInfoSize[%u]\n", frmNo, outBufSize, outFrmSize, outFrmInfoSize);
	}else if(ret == AV_ER_SESSION_CLOSE_BY_REMOTE){
		DEBUG("[thread_ReceiveVideo] AV_ER_SESSION_CLOSE_BY_REMOTE\n");
		return 2;
	}else if(ret == AV_ER_REMOTE_TIMEOUT_DISCONNECT){
		DEBUG("[thread_ReceiveVideo] AV_ER_REMOTE_TIMEOUT_DISCONNECT\n");
		return 2;
	}else if(ret == IOTC_ER_INVALID_SID){
		DEBUG("[thread_ReceiveVideo] Session cant be used anymore\n");
		return 2;
	}else if(ret < 0){
		DEBUG("[thread_ReceiveVideo] Error----------------------->%d\n", ret);
		return 2;
	}else{
		DEBUG("video frame NO[%u] ReadSize[%d] FrmSize[%d] FrmInfoSize[%u]\n", frmNo, outBufSize, outFrmSize, outFrmInfoSize);
	}
	tmlen = file_mod_write(1, buf, ret);
	DEBUG("Write File:%d/%d\n", tmlen, ret);

	return 0;	
}

void* thread_av_mod(void *arg)
{
	av_mod_context *av_context = (av_mod_context *)arg;
	int ret;

	if(!av_context){
		DEBUG("Parameter NULL\n");
		return NULL;
	}

	while(1){
		if(av_context->status == AV_CONFIG_OK){
			DEBUG("Connect IPCamera[%s:%s:%s]...\n", av_context->username, 
					av_context->password, av_context->uid);
			
			pthread_mutex_lock(&v_lock);
			ret = av_mod_conncet(av_context);			
			if(ret < 0){
				DEBUG("Connect Failed\n");				
				pthread_mutex_unlock(&v_lock);
				sleep(1);
				continue;
			}
			av_context->status = AV_CNT_OK;
			av_context->online = 1;			
			pthread_mutex_unlock(&v_lock);
		}else if(av_context->status == AV_INIT){
			usleep(200000);
			continue;
		}
		if(av_context->status != AV_CNT_OK){
			DEBUG("Connect Status Error:%d\n", av_context->status);
			av_context->status = AV_CONFIG_OK;
		}
		/*Receive Video Stream*/
		ret = av_mod_recvvideo(av_context->avIndex);
		if(ret == 1){
			usleep(20000);
			continue;
		}else if(ret == 2){
		
			avClientStop(av_context->avIndex);	
			IOTC_Session_Close(av_context->sid);
		
			pthread_mutex_lock(&v_lock);
			av_context->status = AV_CONFIG_OK;			
			av_context->online = 0;			
			pthread_mutex_unlock(&v_lock);
			usleep(200000);
		}
	}
}

int av_mod_init(void)
{
	int ret, avVer;;
	unsigned int iotcVer;
	char szIOTCVer[16], szAVVer[16];

	memset(&av_modcnt, 0, sizeof(av_modcnt));
	
	ret = IOTC_Initialize2(0);
	if(ret != IOTC_ER_NoERROR){
		DEBUG("IOTC_Initialize2 Error:%d\n", ret);
		return -1;
	}

	avInitialize(32);

	IOTC_Get_Version(&iotcVer);
	avVer = avGetAVApiVer();
	unsigned char *p = (unsigned char *)&iotcVer;
	unsigned char *p2 = (unsigned char *)&avVer;
	sprintf(szIOTCVer, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);	
	sprintf(szAVVer, "%d.%d.%d.%d", p2[3], p2[2], p2[1], p2[0]);	
	DEBUG("IOTCAPI version[%s] AVAPI version[%s]\n", szIOTCVer, szAVVer);

	if(av_mod_conf_restore(&av_modcnt) == 0){
		av_modcnt.status = AV_CONFIG_OK;
	}
	
	ret = pthread_create(&av_modcnt.pid, NULL, thread_av_mod, (void *)&av_modcnt);
	if(ret != 0){
		DEBUG("Create Thread Failed:%d\n", ret);
		return -1;
	}

	return 0;
}


int av_mod_setinfo(char *username, char *password, char *uid)
{
	if(!username || !password || !uid){
		return -1;
	}
	pthread_mutex_lock(&v_lock);
	strncpy(av_modcnt.username, username, sizeof(av_modcnt.username)-1);
	strncpy(av_modcnt.password, password, sizeof(av_modcnt.password)-1);
	strncpy(av_modcnt.uid, uid, sizeof(av_modcnt.uid)-1);
	/*Set FLAG*/
	if(av_modcnt.online == 1){
		DEBUG("DisAble Connect First...\n");
		avClientStop(av_modcnt.avIndex);	
		IOTC_Session_Close(av_modcnt.sid);	
	}
	av_modcnt.status = AV_CONFIG_OK;			
	av_modcnt.online = 0;
	
	av_mod_conf_save(&av_modcnt);
	pthread_mutex_unlock(&v_lock);

	DEBUG("Update Config Successful:%s/%s/%s\n", username, password, uid);

	return 0;
}

int av_mod_status(struct ipcam_info *av_info)
{
	if(!av_info){
		return -1;
	}
	memset(av_info, 0, sizeof(struct ipcam_info));
	if(strlen(av_modcnt.username)){
		strncpy(av_info->username, av_modcnt.username, sizeof(av_info->username)-1);
	}
	if(strlen(av_modcnt.password)){
		strncpy(av_info->password, av_modcnt.password, sizeof(av_info->password)-1);
	}
	if(strlen(av_modcnt.uid)){
		strncpy(av_info->uid, av_modcnt.uid, sizeof(av_info->uid)-1);
	}
	av_info->online = av_modcnt.online;

	DEBUG("Information:%s/%s/%d\n", av_info->username, av_info->password, av_info->online);
	return 0;
}

int av_mod_status2(int *av_ok)
{
	if(!av_ok){
		return -1;
	}

	*av_ok = av_modcnt.online;

	return 0;
}
