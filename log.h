#ifndef _LOG_H
#define _LOG_H

#include <sys/types.h>
#include <sys/socket.h>

#define DEBUG(fmt, arg...) do {log_debug(stderr, __FILE__, __FUNCTION__ ,  __LINE__, fmt, ##arg); } while (0)


#endif
