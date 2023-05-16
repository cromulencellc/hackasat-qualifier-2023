#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <fcntl.h>
#include "dictionary.h"
#include "config.h"
#include "debug.h"

#define MAX_LINE_SIZE 1024


dictionaryType *loadINI(char *filename) {

FILE *fp;
char line[MAX_LINE_SIZE];
dictionaryType *configDict =NULL;

    fp = fopen(filename, "r");

    if (fp == NULL)
        return NULL;

    while(fgets(line, MAX_LINE_SIZE, fp)) {

		debug("line = %s\n", line);
        // a valid line must start with a character
        if ( !isalpha(*line))
            continue;

        if (line[0] == '#')
            continue;

        addDictbyLine(&configDict, line, ':');

    }

    fclose(fp);

    return configDict;

}
