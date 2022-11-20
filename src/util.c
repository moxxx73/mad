#include "util.h"

int isfile(char *name_ptr){
	struct stat throwaway;
	if(!name_ptr) return 0;
	if(stat(name_ptr, &throwaway) < 0) return 0;
	return 1;
}
