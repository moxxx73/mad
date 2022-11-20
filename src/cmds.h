#ifndef CMDS_H
#define CMDS_H

typedef struct{
	long length;
	char *buf;
} CMD;

typedef struct args_str{
	char *str;
	long length;
	struct args_str *fw;
} ARG;

typedef struct{
	char *cmd;
	long cmdlength;
	long arg_count;
	ARG *args;
} PCMD;

void elf_cmd_help(void);

int elf_cmd_handler(PCMD *pcmd);

void mad_help(void);

#endif