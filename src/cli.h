#ifndef CLI_H
#define CLI_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pool.h"
#include "cmds.h"

#define CMDSIZE 256
#define PROMPT "mad>"

void freecmd(CMD *cmd);

CMD *getcmd(void);

void free_pcmd(PCMD *pcmd);

PCMD *parse_cmd(CMD *cmd);

int run_cmd(PCMD *cmd);

#endif