#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "util.h"
#include "pool.h"
#include "cli.h"
#include "madELF.h"

ELF *elf = NULL;
char *elfpath = NULL;
int pid = 0;

void usage(char *az){
	printf("%s [Flags] [ELF|PID]\n", az);
	printf("\t-p [PID]: Attach to existing process\n");
	exit(0);
}

void mad_main(void){
	CMD *cmd = NULL;
	PCMD *pcmd = NULL;
	if(elfpath && pid == 0){
		elf = loadELF(elfpath);
		if(!elf) fprintf(stderr, "Failed to load ELF %s\n", elfpath);
		else import_ptr((void *)elf, (void (*)(void *))&free_elf);
	}
	printf("CTRL^C || \"quit\" to exit\n\n");
	for(;;){
		cmd = getcmd();
		if(cmd){
			import_ptr(cmd, (void(*)(void *))&freecmd);
			if(cmd->length >= 1){
				pcmd = parse_cmd(cmd);
				if(pcmd){
					run_cmd(pcmd);
					free_pcmd(pcmd);
					pcmd = NULL;
				}
			}
			rmptr(cmd);
			cmd = NULL;
		}
	}
	return;
}

void int_handler(__attribute__((unused)) int sig){
	exit(130);
}

int main(int argc, char **argv){
	int x = 1;
	char *np = NULL;
	signal(SIGINT, &int_handler);
	init_pool();

	for(; x < argc; x++){
		if((argv[x][0] == '-') && (strlen(argv[x]) >= 2)){
			switch(argv[x][1]){
				case 'p':
					if((x+1) < argc){
						pid = atoi(argv[x+1]);
						if(!pid){
							fprintf(stderr, "Invalid process ID provided\n");
							return 1;
						}
						x++;
						break;
					}
					break;
				case 'h':
					usage(argv[0]);
			}
		}
		else{
			np = argv[x];
			if(isfile(np) && !elfpath){
				elfpath = strdup(np);
				if(import_ptr(elfpath, &free) != elfpath) return 1;
				printf("Debugging %s...\n", elfpath);
			}
		}
	}
	if(elfpath && pid){
		fprintf(stderr, "you cant specify both a PID and Executable... yet\n");
		return 1;
	}
	mad_main();
	return 0;
}