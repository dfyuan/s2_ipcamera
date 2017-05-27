#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
 #include <sys/stat.h>
 #include <fcntl.h>
 #include <errno.h>
#include <mntent.h>

#include "log.h"
#include "file_mod.h"
#include "av_mod.h"



#define DEFAULT_FPS			10
#define FFMPEGCMD			"/usr/bin/ffmpeg -y -framerate %d  -i %s   -vcodec copy %s"
/*************************************************************************************/
/*************************************STRUCT DEFINE***********************************/
/*************************************************************************************/

#define TIME_DEFAULT_SEG		60 /*second*/
#define FILE_DEFAULT_NAME		"video.raw"
pthread_cond_t m_cond=PTHREAD_COND_INITIALIZER;

typedef struct _file_mod_contex_t{
	int file_fd;
	pthread_t file_pid;
	int file_finish;
	int time_segment;
	pthread_mutex_t f_lock;
	char save_path[4096];

	int (*file_open)(char *);
	int (*file_close)(void);
	int (*file_write)(int, unsigned char*, int);
	int (*av_get_status)(int*);
	int (*file_chk_path)(char *);
}file_mod_cnt;

static file_mod_cnt file_context;

/*************************************************************************************/
/*************************************PRIVATE FUNCTION********************************/
/*************************************************************************************/

static int func_convert_rename(char *name, char *savepath)
{
	char cmd[4096] = {0};
	if(!name || !savepath){
		return -1;
	}

	snprintf(cmd, sizeof(cmd)-1, FFMPEGCMD, DEFAULT_FPS, name, savepath);
	DEBUG("Do Cmd-->%s\n", cmd);
	system(cmd);

	if(access(savepath) != 0){
		DEBUG("FFmpeg Successfull[%s]\n", savepath);

		return 0;
	}

	return -1;
}

static int func_file_open(char *name)
{
	int fd;
	
	if(!name){
		return -1;
	}
	pthread_mutex_lock(&file_context.f_lock);	
	fd = open(name, O_CREAT|O_TRUNC|O_RDWR, 0755);
	if(fd < 0){ 
		if(errno == EROFS){
			DEBUG("Read Only...\n",name);
		}
		close(fd);
		file_context.file_fd = -1;
		pthread_mutex_unlock(&file_context.f_lock);
		return -1;
	}
	file_context.file_fd = fd;
	file_context.file_finish = 0;
	DEBUG("file FD is %d\n",fd);
	pthread_mutex_unlock(&file_context.f_lock);

	return fd;
}

static int func_file_close(void)
{
	int ret = 0;
	
	pthread_mutex_lock(&file_context.f_lock);

	while(file_context.file_finish == 0){
		pthread_cond_wait(&m_cond, &file_context.f_lock);
	}
	
	close(file_context.file_fd);
	file_context.file_fd = -1;
	if(file_context.file_finish == -1){
		DEBUG("Wrtie Error\n");
	}else if(file_context.file_finish == 1){
		DEBUG("Part File Write Finish...\n");
	}
	ret = file_context.file_finish;
	file_context.file_finish = 0;
	pthread_mutex_unlock(&file_context.f_lock);

	return ret;
}

static int func_file_write(int decode, unsigned char *content, int len)
{
	int wsize = 0;
	static int fpscnt = 0;
	
	if(!content || !len){
		return 0;
	}
	pthread_mutex_lock(&file_context.f_lock);
	if(file_context.file_fd<= 0){
		DEBUG("File Not Ready\n");
		pthread_mutex_unlock(&file_context.f_lock);
		return 0;
	}
	if(decode == 1){
		DEBUG("Need Decode Buffer[%d]...\n", len);

	}

	wsize = write(file_context.file_fd, content, len);
	if(wsize != len){
		fpscnt = 0;
		file_context.file_finish = -1;		
		DEBUG("Write Error[%d/%d][%s]\n", wsize, len, strerror(errno));
		pthread_cond_broadcast(&m_cond);
	}else/*signal to wait thread*/if(fpscnt++ == DEFAULT_FPS*file_context.time_segment){
		DEBUG("File Write Finish, Need To convert[%d]...\n", fpscnt);
		fpscnt = 0;
		file_context.file_finish = 1;
		pthread_cond_broadcast(&m_cond);
	}
	pthread_mutex_unlock(&file_context.f_lock);

	return wsize;
}

int check_dev(char *dev)
{
	FILE *pfp = NULL;
	char line[512] = {0};	
	int ma, mi, sz, flag = 0;
	char ptname[100];
	char devname[256] = {0}, *ptr=NULL;

	ptr = strrchr(dev, '/');
	if(ptr != NULL){
		strcpy(devname, ++ptr);
	}else{
		strcpy(devname, dev);
	}
	
	pfp = fopen("/proc/partitions", "r");
	if(pfp == NULL){
		DEBUG("Fopen /proc/partitions failed\n");
		return -1;
	}

	while(fgets(line, 512, pfp)){
		if (sscanf(line, " %d %d %d %[^\n ]",
				&ma, &mi, &sz, ptname) != 4){
			continue;
		}	
		if(strstr(devname, ptname)==NULL){
			continue;
		}
		flag = 1;
		break;
	}
	fclose(pfp);

	return (flag == 1?0:-1);
}

int check_partrdonly(char *path)
{
	char filename[4096] = {0};
	int fd;
	
	if(path == NULL){
		return -1;
	}

	sprintf(filename, "%s/.readonly.tst", path);
	fd = open(filename, O_CREAT|O_TRUNC|O_RDWR, 0755);
	if(fd < 0 && errno == EROFS){
		printf("[%s:%d][%s] Read Only...\n", __func__, __LINE__, path);
		close(fd);
		return 0;
	}
	close(fd);
	remove(filename);
	
	return -1;
}


static int func_file_chk_path(char *path)
{

	struct mntent *mnt; 	
	FILE *fp = NULL;
	char bckpath[4096] = {0};
	
	if(!path){
		return -1;
	}
	
	fp = setmntent("/proc/mounts", "r");
	if(fp == NULL){
		return -1;
	}
	while ((mnt = getmntent(fp))){
		if (strstr(mnt->mnt_dir, "Volume")){
			if(check_dev(mnt->mnt_fsname) < 0){
				continue;
			}
			if(check_partrdonly(mnt->mnt_dir) == 1){
				DEBUG("************The partion is: \"%s\" Readonly\n", mnt->mnt_dir);
				continue;
			}
		//	if (strlen(path) && !strcmp(mnt->mnt_dir, path)){		
			if (strlen(path) && !strncmp(path, mnt->mnt_dir, strlen(mnt->mnt_dir))){
				/*We need to check partition*/
				DEBUG("Check %s Successful\n", path);				
				endmntent(fp);
				return 0;
			}
			if(!strlen(bckpath)){
				DEBUG("Backup Path:%s\n", mnt->mnt_dir);
				strcpy(bckpath, mnt->mnt_dir);
				snprintf(bckpath, sizeof(bckpath)-1, "%s/%s", mnt->mnt_dir, "IPCamera");
				if(access(bckpath)){
					mkdir(bckpath, 0777);
				}
			}
		}
	}	
	endmntent(fp);

	strcpy(path, bckpath);

	DEBUG("Update Path:%s\n", path);
	return 0;	
}


static void *thread_file_mod(void *arg)
{
	file_mod_cnt *file_cnt_context = (file_mod_cnt *)arg;
	int av_ok;
	int file_fd, cur = 0;
	char file_path[4096] = {0};
	int ret;
	time_t begin, end;

	if(!file_cnt_context){
		DEBUG("Parameter NULL\n");
		return NULL;
	}

	while(1){
		if(file_cnt_context->av_get_status(&av_ok) < 0){
			DEBUG("Get AV Status Error\n");
			usleep(50000);
			continue;
		}else if(!av_ok){
		//	DEBUG("Status Not Ready[AV=%d]\n", av_ok);
			usleep(20000);
			continue;
		}
		if(file_cnt_context->file_chk_path(file_cnt_context->save_path) < 0){
			DEBUG("Disk Not Ready\n");			
			memset(file_path, 0, sizeof(file_path));
			usleep(500000);
			continue;
		}else if(!strlen(file_path)){
			snprintf(file_path, sizeof(file_path)-1, "%s/%s", file_cnt_context->save_path, FILE_DEFAULT_NAME);			
			DEBUG("Save Video Path is %s\n", file_path);			
		}		
		begin = time(NULL);
		file_fd = file_cnt_context->file_open(file_path);
		if(file_fd < 0){
			DEBUG("file_open Failed:%d\n", file_fd);
			usleep(500000);
			continue;
		}
		
		/*Close and rename*/
		ret = file_cnt_context->file_close();
		if(ret < 0){
			continue;
		}else if(ret == 1){	
			end = time(NULL);
			char savepath[4096] = {0};
			DEBUG("Write File Cost %ld, Convert Rename File %s\n", end-begin, file_path);			
			struct tm *tmb, tmptmb={0}, *tme, tmptme={0};
			localtime_r(&begin, &tmptmb);	
			tmb=&tmptmb;
			localtime_r(&end, &tmptme);	
			tme=&tmptme;
			snprintf(savepath, sizeof(savepath)-1, "%s/%02d_%02d_%02d_%02d_%02d-%02d_%02d_%02d.mp4",
							file_cnt_context->save_path, tmb->tm_mon+1, tmb->tm_mday, tmb->tm_hour, tmb->tm_min, tmb->tm_sec, 
								tme->tm_hour, tme->tm_min, tme->tm_sec);
			DEBUG("Save File is %s\n", savepath);
			
			func_convert_rename(file_path, savepath);
		}
	}

	return;
}



/*************************************************************************************/
/*************************************PUBLIC FUNCTION*********************************/
/*************************************************************************************/



int file_mod_init(int time_internal)
{
	int rc;
	
	memset(&file_context, 0, sizeof(file_mod_cnt));
	/*init mutex lock*/
	pthread_mutex_init(&file_context.f_lock, NULL);
	/*Set time internal to spilt file*/
	if(time_internal > 0){
		file_context.time_segment = time_internal;
	}else{
		file_context.time_segment = TIME_DEFAULT_SEG;
	}

	file_context.file_open = func_file_open;
	file_context.file_close = func_file_close;
	file_context.file_write = func_file_write;
	file_context.file_chk_path = func_file_chk_path;
	file_context.av_get_status = av_mod_status2;

	file_context.file_chk_path(file_context.save_path);
	/*start file thread*/
	
	rc = pthread_create(&file_context.file_pid, NULL, thread_file_mod, (void *)&file_context);
	if(rc != 0){
		DEBUG("Create Thread Failed:%d\n", rc);
		return -1;
	}

	return 0;
}

int file_mod_write(int decode, char *buf, int len)
{
	if(!buf || len <= 0){
		return -1;
	}

	return func_file_write(decode, (unsigned char *)buf, len);
}
