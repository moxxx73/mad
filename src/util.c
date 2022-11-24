#include "util.h"
#include <string.h>
#include <assert.h>

int isfile(char *name_ptr){
	struct stat throwaway;
	if(!name_ptr) return 0;
	if(stat(name_ptr, &throwaway) < 0) return 0;
	return 1;
}

int has_char(char *str, char b){
	int slen = 0, x = 0;
	assert(str);
	slen = strlen(str);
	for(; x < slen; x++){
		if(str[x] == b) return 1;
	}
	return 0;
}