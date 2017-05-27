#ifndef _AV_MOD_H
#define _AV_MOD_H

struct ipcam_info{
	char username[256];
	char password[256];
	char uid[256];
	int online;	
};

int av_mod_init(void);
int av_mod_setinfo(char *username, char *password, char *uid);
int av_mod_status(struct ipcam_info *av_info);
int av_mod_status2(int *av_ok);

#endif
