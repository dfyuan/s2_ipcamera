#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdarg.h>
#include "log.h"

static pthread_mutex_t m_mulog=PTHREAD_MUTEX_INITIALIZER;

void log_debug(FILE *fp, char *fname, const char *func, int lineno, char *fmt, ...)
{
	va_list ap;
	pid_t pid;

	pthread_mutex_lock(&m_mulog);	
	if (fp == NULL)
		fp=stderr;

	pid = getpid();
		
	time_t t;
	struct tm *tm, tmptm={0};
	t = time(NULL);
	localtime_r(&t, &tmptm);
	tm=&tmptm;
	fprintf(fp, "[%04d/%02d/%02d %02d:%02d:%02d] ",
			tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	
	fprintf(fp, "[pid:%d] ", pid);
	
	fprintf(fp, "(%s:%s():%d) ", fname, func, lineno);

	va_start(ap, fmt);
	if (vfprintf(fp, fmt, ap) == -1)
	{
		va_end(ap);		
		pthread_mutex_unlock(&m_mulog);	
		return;
	}
	va_end(ap);

	fflush(fp);
	pthread_mutex_unlock(&m_mulog); 
	return;
}

