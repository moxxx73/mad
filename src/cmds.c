#include "cmds.h"
#include <stdio.h>
#include <string.h>
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
	if(pcmd->arg_count >= 1){
		switch(pcmd->args->length){
			// parse subcommands for elf
			case 4:
				if(strncmp(pcmd->args->str, "help", 4) == 0){
					elf_cmd_help();
					return 0;
				}
				break;
			case 3:
				if(strncmp(pcmd->args->str, "hdr", 3) == 0){
					print_elf_hdr(elf);
					return 0;
				}
				break;
		}
		return 0;
	}
	return -1;
}

void mad_help(void){
	printf("Implemented commands:\n");
	printf(" - elf [subcommand] [args...] ; Inspecting the ELF file structure\n");
	printf("\nFor help with commands just do: <cmd> help\n");
	return;
}