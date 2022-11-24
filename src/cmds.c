#include "cmds.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "madELF.h"

extern ELF *elf;

void elf_cmd_help(void){
	printf("Usage: elf [subcommand] [args...]\n");
	printf("== Subcommands ==\n");
	printf("   hdr:   Display ELF header\n");
	printf("   phdrs: Display program headers\n");
	printf("   shdrs: Display section headers\n");
	printf("   syms:  List symbols\n");
	return;
}

int elf_cmd_handler(PCMD *pcmd){
	assert(pcmd);
	if(pcmd->cmdlength > 1){
		switch(pcmd->cmd[1]){
			case '?':
				elf_cmd_help();
				return 0;
			case 'h':
				print_elf_hdr(elf);
				return 0; 
		}
	}
	return 0;
}

void mad_help(void){
	printf("Implemented commands:\n");
	printf(" e[?]: Inspecting the ELF file structure\n");
	printf("\nFor help with commands just do: <cmd> help\n");
	return;
}