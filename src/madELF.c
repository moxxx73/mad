#include "madELF.h"

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

char *str_abi(char abi){
	switch(abi){
		case ELFOSABI_SYSV:
			return "UNIX System V";
		default:
			return "Unknown";
	}
	return NULL;
}

char *str_etype(unsigned short e_type){
	switch(e_type){
		case ET_REL:
			return "Relocatable";
		case ET_EXEC:
			return "Executable";
		case ET_DYN:
			return "Shared Object";
		case ET_CORE:
			return "Core File";
		default:
			return "Not Implemented"; 
	}
	return NULL;
}

char *str_eidata(char ei_data){
	switch(ei_data){
		case ELFDATA2LSB:
			return "2's complement, little endian";
		default:
			return "2's complement, big endian";
	}
	return NULL;
}

char *str_emachine(unsigned short e_machine){
	switch(e_machine){
		case EM_386:
			return "Intel 80386";
		case EM_MIPS:
			return "MIPS R3000 Big-Endian";
		case EM_MIPS_RS3_LE:
			return "MIPS R3000 Little-Endian";
		case EM_ARM:
			return "ARM";
		case EM_X86_64:
			return "AMD x86-64";
		case EM_AARCH64:
			return "ARM AARCH64";
		case EM_RISCV:
			return "RISC-V";
		default:
			return "Not Implemented";
	}
	return NULL;
}

char *str_ptype(uint32_t type){
	switch(type){
		case PT_NULL:
			return "NULL";
		case PT_LOAD:
			return "LOAD";
		case PT_DYNAMIC:
			return "DYNAMIC";
		case PT_INTERP:
			return "INTERP";
		case PT_NOTE:
			return "NOTE";
		case PT_SHLIB:
			return "SHLIB";
		case PT_PHDR:
			return "PHDR";
		case PT_TLS:
			return "TLS";
		case PT_NUM:
			return "NUM";
		case PT_LOOS:
			return "LOOS";
		case PT_GNU_EH_FRAME:
			return "GNU_EH_FRAME";
		case PT_GNU_STACK:
			return "GNU_STACK";
		case PT_GNU_RELRO:
			return "GNU_RELRO";
		case PT_GNU_PROPERTY:
			return "GNU_PROPERTY";
		case PT_LOSUNW:
			return "LOSUNW";
		case PT_SUNWSTACK:
			return "SUNWSTACK";
		case PT_HIOS:
			return "HIOS";
		case PT_LOPROC:
			return "LOPROC";
		case PT_HIPROC:
			return "HIPROC";
		default:
			return "INVALID";
	}
}

char *str_shtype(uint32_t sh_type){
	switch(sh_type){
		case SHT_NULL:
			return "NULL";
		case SHT_PROGBITS:
			return "PROGBITS";
		case SHT_SYMTAB:
			return "SYMTAB";
		case SHT_STRTAB:
			return "STRTAB";
		case SHT_RELA:
			return "RELA";
		case SHT_HASH:
			return "HASH";
		case SHT_DYNAMIC:
			return "DYNAMIC";
		case SHT_NOTE:
			return "NOTE";
		case SHT_NOBITS:
			return "NOBITS";
		case SHT_REL:
			return "REL";
		case SHT_SHLIB:
			return "SHLIB";
		case SHT_DYNSYM:
			return "DYNSYM";
		case SHT_INIT_ARRAY:
			return "INIT_ARRAY";
		case SHT_FINI_ARRAY:
			return "FINI_ARRAY";
		case SHT_PREINIT_ARRAY:
			return "PREINIT_ARRAY";
		case SHT_GROUP:
			return "GROUP";
		case SHT_SYMTAB_SHNDX:
			return "SYMTAB_SHNDX";
		case SHT_NUM:
			return "NUM";
		case SHT_LOOS:
			return "LOOS";
		case SHT_GNU_ATTRIBUTES:
			return "GNU_ATTRIBUTES";
		case SHT_GNU_HASH:
			return "GNU_HASH";
		case SHT_GNU_LIBLIST:
			return "GNU_LIBLIST";
		case SHT_CHECKSUM:
			return "CHECKSUM";
		case SHT_LOSUNW:
			return "LOSUNW";
		case SHT_SUNW_COMDAT:
			return "SUNW_COMDAT";
		case SHT_SUNW_syminfo:
			return "SUNW_syminfo";
		case SHT_GNU_verdef:
			return "GNU_verdef";
		case SHT_GNU_verneed:
			return "GNU_verneed";
		case SHT_GNU_versym:
			return "GNU_versym";
		case SHT_LOPROC:
			return "LOPROC";
		case SHT_HIPROC:
			return "HIPROC";
		case SHT_LOUSER:
			return "LOUSER";
		case SHT_HIUSER:
			return "HIUSER";
		default:
			return "INVALID";
	}
}

void free_ptr_array(void **array, int64_t length){
	int index = 0;
	if(!array || (length <= 0) ) return;

	for(; index < length; index++){
		if(array[index]){
			free(array[index]);
			array[index] = NULL;
		}
	}
	free(array);
	return;
}

void free_elf(ELF *elf){
	if(elf){
		if(elf->fdata) free(elf->fdata);
		
		if(elf->phdrs) free_ptr_array((void **)elf->phdrs, elf->hdr->e_phnum);
		if(elf->shdrs) free_ptr_array((void **)elf->shdrs, elf->hdr->e_shnum);

		if(elf->hdr) free(elf->hdr);
		memset(elf, 0, sizeof(ELF));
		free(elf);
	}
	return;
}

sym **load_symtab(ELF *elf, section_hdr *symsh){
	sym **symtab = NULL;
	uint64_t index = 0;
	uint64_t offset = 0;
	uint64_t size = 0;
	uint64_t sym_count = 0;
	char *datap = NULL;
	if(!elf || !symsh) return NULL;
	
	datap = elf->fdata;
	offset = symsh->sh_offset;
	size = symsh->sh_size;
	if((offset > elf->fdata_size) || ((offset+size) > elf->fdata_size)){
		return NULL;
	}
	datap += offset;
	sym_count = size/symsh->sh_entsize;
	symtab = (sym **)malloc((sizeof(sym *)*sym_count+1));
	if(!symtab){
		fprintf(stderr, "load_symtab(): %s\n", strerror(errno));
		return NULL;
	}
	memset(symtab, 0, (sizeof(sym *)*sym_count+1));
	for(; index < sym_count; index++){
		symtab[index] = (sym *)malloc(sizeof(sym));
		if(!symtab){
			fprintf(stderr, "load_symtab(): %s\n", strerror(errno));
			goto LOAD_SYMTAB_ERR;
		}
		symtab[index]->st_name = *(uint32_t *)(datap);
		datap += 4;
		if(elf->hdr->e_ident[4] == ELFCLASS64){
			symtab[index]->st_info = *(uint8_t *)(datap);
			symtab[index]->st_other = *(uint8_t *)(datap+1);
			symtab[index]->st_shndx = *(uint16_t *)(datap+2);
			symtab[index]->st_value = *(uint64_t *)(datap+4);
			symtab[index]->st_size = *(uint64_t *)(datap+12);
			datap += 20;
		}else{
			symtab[index]->st_value = *(uint32_t *)(datap);
			symtab[index]->st_size = *(uint32_t *)(datap+4);
			symtab[index]->st_info = *(uint8_t *)(datap+8);
			symtab[index]->st_other = *(uint8_t *)(datap+9);
			symtab[index]->st_shndx = *(uint16_t *)(datap+10);
			datap += 12;
		}

	}
	return symtab;
LOAD_SYMTAB_ERR:
	free_ptr_array((void **)symtab, sym_count);
	return NULL;

}

section_hdr **parse_shdrs(elf_hdr *hdr, char *fdata, uint64_t fdata_size){
	char *dp = NULL;
	int index = 0;
	section_hdr **shdrs=NULL;
	if(!hdr || !fdata || (fdata_size <= 0)){
		fprintf(stderr, "parse_shdrs(): Bad arguments\n");
		return NULL;
	}
	dp = (fdata+hdr->e_shoff);
	shdrs = (section_hdr **)malloc((sizeof(section_hdr *)*(hdr->e_shnum+1)));
	if(!shdrs){
		fprintf(stderr, "parse_shdrs(): %s\n", strerror(errno));
		return NULL;
	}
	memset(shdrs, 0, (sizeof(section_hdr *)*(hdr->e_shnum+1)));
	for(; index < hdr->e_shnum; index++){
		if(!(shdrs[index] = (section_hdr *)malloc(sizeof(section_hdr)))){
			fprintf(stderr, "parse_shdrs(): %s\n", strerror(errno));
			goto PARSE_SHDRS_ERR;
		}
		memset(shdrs[index], 0, sizeof(section_hdr));
		shdrs[index]->sh_name = *(uint32_t *)(dp);
		shdrs[index]->sh_type = *(uint32_t *)(dp+4);
		dp += 8;
		if(hdr->e_ident[4] == ELFCLASS64){
			shdrs[index]->sh_flags = *(uint64_t *)(dp);
			shdrs[index]->sh_addr = *(uint64_t *)(dp+8);
			shdrs[index]->sh_offset = *(uint64_t *)(dp+16);
			shdrs[index]->sh_size = *(uint64_t *)(dp+24);
			shdrs[index]->sh_link = *(uint32_t *)(dp+32);
			shdrs[index]->sh_info = *(uint32_t *)(dp+36);
			shdrs[index]->sh_addralign = *(uint64_t *)(dp+40);
			shdrs[index]->sh_entsize = *(uint64_t *)(dp+48);
			dp += 56;
		}else{
			shdrs[index]->sh_flags = *(uint32_t *)(dp);
			shdrs[index]->sh_addr = *(uint32_t *)(dp+4);
			shdrs[index]->sh_offset = *(uint32_t *)(dp+8);
			shdrs[index]->sh_size = *(uint32_t *)(dp+12);
			shdrs[index]->sh_link = *(uint32_t *)(dp+16);
			shdrs[index]->sh_info = *(uint32_t *)(dp+20);
			shdrs[index]->sh_addralign = *(uint32_t *)(dp+24);
			shdrs[index]->sh_entsize = *(uint32_t *)(dp+28);
			dp += 32;
		}
	}
	return shdrs;
PARSE_SHDRS_ERR:
	free_ptr_array((void **)shdrs, hdr->e_shnum);
	return NULL;
}

program_hdr **parse_phdrs(elf_hdr *hdr, char *fdata, uint64_t fdata_size){
	char *dp = NULL;
	int index = 0;
	program_hdr **phdrs=NULL;
	if(!hdr || !fdata || (fdata_size <= 0)){
		fprintf(stderr, "parse_phdrs(): Bad arguments\n");
		return NULL;
	}
	
	dp = (fdata+hdr->e_phoff);
	phdrs = (program_hdr **)malloc((sizeof(program_hdr *)*(hdr->e_phnum+1)));
	if(!phdrs){
		fprintf(stderr, "parse_phdrs(): %s\n", strerror(errno));
		return NULL;
	}
	memset(phdrs, 0, (sizeof(program_hdr *)*(hdr->e_phnum+1)));
	for(; index < hdr->e_phnum; index++){
		if(!(phdrs[index] = (program_hdr *)malloc(sizeof(program_hdr)))){
			fprintf(stderr, "parse_phdrs(): %s\n", strerror(errno));
			goto PARSE_PHDRS_ERR;
		}
		memset(phdrs[index], 0, sizeof(program_hdr));
		phdrs[index]->p_type = *(uint32_t *)(dp);
		dp += 4;
		if(hdr->e_ident[4] == ELFCLASS64){
			phdrs[index]->p_flags = *(uint32_t *)(dp);
			phdrs[index]->p_offset = *(uint64_t *)(dp+4);
			phdrs[index]->p_vaddr = *(uint64_t *)(dp+12);
			phdrs[index]->p_paddr = *(uint64_t *)(dp+20);
			phdrs[index]->p_filesz = *(uint64_t *)(dp+28);
			phdrs[index]->p_memsz = *(uint64_t *)(dp+36);
			phdrs[index]->p_align = *(uint64_t *)(dp+44);
			dp += 52;
		}else{
			phdrs[index]->p_offset = *(uint32_t *)(dp);
			phdrs[index]->p_vaddr = *(uint32_t *)(dp+4);
			phdrs[index]->p_paddr = *(uint32_t *)(dp+8);
			phdrs[index]->p_filesz = *(uint32_t *)(dp+12);
			phdrs[index]->p_memsz = *(uint32_t *)(dp+16);
			phdrs[index]->p_flags = *(uint32_t *)(dp+20);
			phdrs[index]->p_align = *(uint32_t *)(dp+24);
			dp += 28;
		}
	}
	return phdrs;
PARSE_PHDRS_ERR:
	free_ptr_array((void **)phdrs, hdr->e_phnum);
	return NULL;
}

elf_hdr *load_ehdr(char *data, unsigned long size){
	char *dp = NULL;
	elf_hdr *ehdr = NULL;
	
	assert(data);
	assert(size >= sizeof(elf_hdr));

	ehdr = (elf_hdr *)malloc(sizeof(elf_hdr));
	if(!ehdr){
		fprintf(stderr, "load_ehdr(): %s\n", strerror(errno));
		goto PARSE_EHDR_ERR;
	};
	memset(ehdr, 0, sizeof(elf_hdr));
	memcpy(ehdr->e_ident, data, EI_NIDENT);
	dp = (data+EI_NIDENT);
	ehdr->e_type = *(uint16_t *)(dp);
	ehdr->e_machine = *(uint16_t *)(dp+2);
	ehdr->e_version = *(uint32_t *)(dp+4);
	dp = (dp+8);
	if(ehdr->e_ident[4] == ELFCLASS64){
		ehdr->e_entry = *(uint64_t *)(dp);
		ehdr->e_phoff = *(uint64_t *)(dp+8);
		ehdr->e_shoff = *(uint64_t *)(dp+16);
		dp = (dp+24);
	}else{
		ehdr->e_entry = *(uint32_t *)(dp);
		ehdr->e_phoff = *(uint32_t *)(dp+4);
		ehdr->e_shoff = *(uint32_t *)(dp+8);
		dp = (dp+12);
	}
	ehdr->e_flags = *(uint32_t *)(dp);
	ehdr->e_ehsize = *(uint16_t *)(dp+4);
	
	ehdr->e_phentsize = *(uint16_t *)(dp+6);
	ehdr->e_phnum = *(uint16_t *)(dp+8);
	ehdr->e_shentsize = *(uint16_t *)(dp+10);
	ehdr->e_shnum = *(uint16_t *)(dp+12);
	ehdr->e_shstrndx = *(uint16_t *)(dp+14);

	return ehdr;

PARSE_EHDR_ERR:
	if(ehdr) free(ehdr);
	return NULL;
}

char *load_shstrtab(ELF *elf){
	section_hdr *strtab_sect = NULL;
	uint64_t sect_size = 0;
	char *table = NULL;

	if(elf->shdrs){
		strtab_sect = elf->shdrs[elf->hdr->e_shstrndx];
		sect_size = strtab_sect->sh_size;
		if((strtab_sect->sh_offset > elf->fdata_size) && ((strtab_sect->sh_offset+sect_size) > elf->fdata_size)) return NULL;
		if(!(table = (char *)malloc(sect_size))){
			fprintf(stderr, "load_shstrtab(): %s\n", strerror(errno));
			return NULL;
		}
		memcpy(table, (elf->fdata+strtab_sect->sh_offset), sect_size);
		return table;
	}
	return NULL;
}

char *load_strtab(ELF *elf, uint64_t offset, uint64_t size){
	char *strtab = NULL;
	char *fdata = NULL;
	uint64_t fdata_size = 0;
	
	if(elf && (offset > 0) && (size > 0)){
		fdata = elf->fdata;
		fdata_size = elf->fdata_size;

		if((offset < fdata_size) || ((offset+size) < fdata_size)){
			fdata += offset;
			strtab = (char *)malloc(size);
			if(!strtab){
				fprintf(stderr, "load_strtab(): %s\n", strerror(errno));
				return NULL;
			}
			memset(strtab, 0, size);
			memcpy(strtab, fdata, size);
			return strtab;
		}
	}
	return NULL;
}

void print_elf_hdr(ELF *elf){
	int x = 0;
	if(!elf){
		fprintf(stderr, "No ELF file loaded\n");
		return;
	}
	if(elf->hdr){
		printf(" Magic: ");
		for(; x < EI_NIDENT; x++){
			printf("%02x ", elf->hdr->e_ident[x]);
		}
		printf("\n");
		printf(" Class:                    ");
		switch(elf->hdr->e_ident[4]){
			case ELFCLASS64:
				printf("ELF64\n");
				break;
			default:
				printf("ELF32\n");
				break; 
		}
		printf(" Data:                     %s\n", str_eidata(elf->hdr->e_ident[5]));
		printf(" ABI:                      %s\n", str_abi(elf->hdr->e_ident[7]));
		printf(" Type:                     %s\n", str_etype(elf->hdr->e_type));
		printf(" Machine:                  %s\n", str_emachine(elf->hdr->e_machine));
		printf(" Version:                  0x%02x\n", elf->hdr->e_version);
		printf(" Entry point:              0x%0lx\n", elf->hdr->e_entry);
		printf(" Start of program headers: %lu (Bytes into file)\n", elf->hdr->e_phoff);
		printf(" Start of section headers: %lu (Bytes into file)\n", elf->hdr->e_shoff);
		printf(" Program header count:     %hu\n", elf->hdr->e_phnum);
		printf(" Program header size:      %hu Bytes\n", elf->hdr->e_phentsize);
		printf(" Section header count:     %hu\n", elf->hdr->e_shnum);
		printf(" Section header size:      %hu Bytes\n", elf->hdr->e_shentsize);
	}
	return;
}

char isELF(char *fdata, unsigned long size){
	unsigned int magic = 0x464c457f;
	assert(size > 4);
	if((*(unsigned int *)fdata) != magic){
		return 0;
	}
	return 1;
}

ELF *loadELF(char *filepath){
	FILE *fp = NULL;
	ELF *elf = NULL;
	struct stat stat_info;

	assert(filepath);
	
	elf = (ELF *)malloc(sizeof(ELF));
	assert(elf);
	memset(elf, 0, sizeof(ELF));

	fp = fopen(filepath, "r");
	assert(fp);
	if(stat(filepath, &stat_info) < 0) goto LOADELF_ERR;
	elf->fdata_size = (uint64_t)stat_info.st_size;
	assert(elf->fdata_size > 0);
	
	printf("Loading file data (%ld Bytes)... ", elf->fdata_size);
	elf->fdata = (char *)malloc(elf->fdata_size);
	if(!elf->fdata) goto LOADELF_ERR;
	memset(elf->fdata, 0, elf->fdata_size);

	if(fread(elf->fdata, 1, elf->fdata_size, fp) != elf->fdata_size){
		printf("Failed\n");
		goto LOADELF_SKIP_OUT;
	}
	fclose(fp);
	fp = NULL;
	printf("Done\n");
	if(!isELF(elf->fdata, elf->fdata_size)){
		fprintf(stderr, "File %s is not a valid ELF file\n", filepath);
		goto LOADELF_SKIP_OUT;
	}

	printf("Loading ELF header... ");
	elf->hdr = load_ehdr(elf->fdata, elf->fdata_size);
	printf("Done\n");

	return elf;

LOADELF_ERR:
	fprintf(stderr, "loadELF(): %s\n", strerror(errno));
LOADELF_SKIP_OUT:
	if(elf) free_elf(elf);
	if(fp) fclose(fp);
	return NULL;
}