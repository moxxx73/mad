#include "cli.h"
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "util.h"

struct termios term_save;
char restore_set = 0;

void freecmd(CMD *cmd){
	if(cmd){
		if(cmd->buf){
			memset(cmd->buf, 0, CMDSIZE);
			free(cmd->buf);
		}
		memset(cmd, 0, sizeof(CMD));
		free(cmd);
	}
	return;
}

void restore_term(void){
	tcsetattr(0, TCSAFLUSH, &term_save);
	return;
}

CMD *getcmd(void){
	CMD *ret = NULL;
	char *bp = NULL;
	int index = 0;
	char tmp = 0x00;

	if(!restore_set){
		atexit(&restore_term);
		restore_set = 1;
	}
	tcgetattr(0, &term_save);
	term_save.c_lflag &= ~(ECHO|ICANON);
	tcsetattr(0, TCSAFLUSH, &term_save);

	ret = (CMD *)malloc(sizeof(CMD));
	memset(ret, 0, sizeof(CMD));
	
	ret->buf = (char *)malloc(CMDSIZE);
	memset(ret->buf, 0, CMDSIZE);
	bp = ret->buf;
	printf("%s ", PROMPT);
	fflush(stdout);
	while(index < (CMDSIZE-1)){
		if(read(0, &tmp, 1) == 1){
			switch(tmp){
				case 27:
					if(read(0, &tmp, 1) == 1){
						if(tmp == 91){
							read(0, &tmp, 1);
							switch(tmp){
								case 68: // left
									if(index > 0){
										index--;
										bp--;
									}
									break;
								case 67: // right
									if((index < (CMDSIZE-1)) && ((unsigned int)index < strlen(ret->buf))){
										index++;
										bp++;
									}
									break;
								default: // not handling the other two for now
									break;
							}
						}
					}
					break;
				case 10:
					restore_term();
					printf("\e[1000D");
					printf("\e[0K");
					printf("%s %s\n", PROMPT, ret->buf);
					ret->length = strlen(ret->buf);
					return ret;
				case 127:
					// add support for deletion mid string
					*bp = 0x00;
					if(index > 0){
						bp--;
						index--;
					}
					break;
				default:
					if((tmp < 127) && (tmp >= 32)){
						if(index < (CMDSIZE-1)){
							index++;
							*bp = tmp;
							bp++;
						}
					}
					break;
			}
		}
		printf("\e[1000D");
		printf("\e[0K");
		printf("%s %s",PROMPT, ret->buf);
		printf("\e[1000D");
		if(index > 0) printf("\e[%dC", (5+index));
		fflush(stdout);
	}
	return ret;
}
/* fist argument (not the list head) is basically argv[0]*/
ARG *parse_args(char *str){
	int clen = 0;
	char *sp = NULL;
	ARG *hd = NULL, *ap = NULL;

	if(!str) return NULL;

	hd = (ARG *)malloc(sizeof(ARG));
	if(!hd){
		fprintf(stderr, "malloc(): %s\n", strerror(errno));
		return NULL;
	}
	memset(hd, 0, sizeof(ARG));
	ap = hd;
	sp = strtok(str, " ");
	while(sp){
		clen = strlen(sp);
		ap->fw = (ARG *)malloc(sizeof(ARG));
		assert(ap->fw);
		
		ap->fw->fw = NULL;

		ap->fw->str = strdup(sp);
		assert(ap->fw->str);

		ap->fw->length = clen;
		
		ap = ap->fw;
		sp = strtok(NULL, " ");
	}
	return hd;
}

void free_args(ARG *args){
	ARG *ap = NULL, *save = NULL;
	ap = args;
	while(ap){
		save = ap->fw;
		if(ap->str) free(ap->str);
		memset(ap, 0, sizeof(ARG));
		free(ap);
		ap = save;
	}
	return;
}

void free_pcmd(PCMD *pcmd){
	ARG *argp = NULL, *save = NULL;
	if(pcmd){
		if(pcmd->cmd) free(pcmd->cmd);
		argp = pcmd->args;
		while(argp){
			if(argp->str) free(argp->str);
			save = argp->fw;
			memset(argp, 0, sizeof(ARG));
			free(argp);
			argp = save;
		}
	}
}

PCMD *parse_cmd(CMD *cmd){
	PCMD *ret = NULL;
	ARG *arg0 = NULL, *argp = NULL;
	if(!cmd) return NULL;
	
	ret = (PCMD *)malloc(sizeof(PCMD));
	if(!ret){
		fprintf(stderr, "malloc(): %s\n", strerror(errno));
		return NULL;
	}
	/*
	if(!has_char(cmd->buf, 0x20)){
		ret->cmd = cmd->buf;
		ret->cmdlength = cmd->length;
		ret->args = NULL;
		return ret;
	}
	*/
	argp = parse_args(cmd->buf);
	if(argp){
		argp = argp->fw;
		if(argp){
			arg0 = argp;
			ret->cmd = arg0->str;
			ret->cmdlength = arg0->length;
			ret->args = arg0->fw;

			argp = ret->args;
			while(argp){
				ret->arg_count += 1;
				argp = argp->fw;
			}
			memset(arg0, 0, sizeof(ARG));
			free(arg0);
		}
	}
	return ret;
}

int run_cmd(PCMD *pcmd){
	if(pcmd){
		if(pcmd->cmd && pcmd->cmdlength){
			switch(pcmd->cmd[0]){
				case 'e':
					elf_cmd_handler(pcmd);
					break;
				case '?':
					mad_help();
					break;
				case 'q':
					exit(0);
				default:
					printf("\"%c\" is not a valid command\n", *((char *)pcmd->cmd));
					printf("Use \"?\" for help\n");
					break;
			}
		}
	}
	return 0;
}