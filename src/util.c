#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "util.h"

void*
xrealloc(void *buf, size_t size)
{
	void *ptr;
	ptr = realloc(buf, size);
	if(!ptr){
		perror("realloc");
		exit(-1);
	}
	return ptr;
}

void*
xmalloc(size_t size)
{
	void *ptr;
	ptr = malloc(size);
	if(!ptr){
		perror("malloc");
		exit(-1);
	}
	return ptr;
}

