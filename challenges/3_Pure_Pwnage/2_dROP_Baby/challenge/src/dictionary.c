
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dictionary.h"
#include "debug.h"


void printDict( dictionaryType *dict ) {

	char separator[] = " : ";
	int max_key_length=0;
	int max_value_length=0;
	char table_title[] = "Config Table";
	dictionaryType *temp;

	temp=dict;
	while(temp != NULL) {

		if (strlen(temp->key) > max_key_length) {
			max_key_length = strlen(temp->key);
		}

		if (strlen(temp->value) > max_value_length) {

			max_value_length = strlen(temp->value);
		}

		temp = temp->next;
	}
	int i;
	temp=dict;

	int total_length = max_key_length+max_value_length+ 5;

	for (i=0;i<(total_length-strlen(table_title))/2;++i)
		putchar(' ');

	printf(table_title);
	putchar('\n');

	for (i=0;i<total_length;++i)
		putchar('-');
	putchar('\n');

	while(temp != NULL) {

		putchar('|');
		for (i=0;i<max_key_length-strlen(temp->key);++i)
			putchar(' ');

		printf(temp->key);
		printf(" : ");

		printf(temp->value);

		for (i=0;i<max_value_length-strlen(temp->value);++i)
			putchar(' ');
		putchar('|');
		putchar('\n');

		temp = temp->next;
	}

	for (i=0;i<total_length;++i)
		putchar('-');
	putchar('\n');

}

int addDictEntry( dictionaryType **dict, char *key, char*value) {

dictionaryType *tempDict;

	if (dict == NULL) {

		return -1;
	}
	if (*dict == 0) {

		*dict = calloc( sizeof(dictionaryType),1);

		if ( *dict == 0 ) {

			return -1;
		}

		tempDict = *dict;

	}
	else {

		tempDict = *dict;

		while( tempDict->next != 0)
			tempDict = tempDict->next;

		tempDict->next = calloc( sizeof(dictionaryType),1);

		if ( tempDict->next == 0 ) {

			return -1;
		}

		tempDict = tempDict->next;
	}

	tempDict->key = calloc( strlen(key)+1 ,1);
	tempDict->value= calloc( strlen(value)+1,1 );
	tempDict->next = 0;

	if ( tempDict->key == 0 || tempDict->value == 0 ) {

		return -1;
	}

	strcpy(tempDict->key, key);
	strcpy(tempDict->value, value);

	return 0;

}

int addDictbyLine( dictionaryType **dict, char *line, char delim) {
	
//dictionaryType *tempDict;
//char key[30];
char *value;

	
	if (!line || strlen( line ) == 0 ) {

		debug("line is 0\n");
		return -1;
	}

	//make sure the key starts with an alpha and number character
	if (!isalnum(*line)) {

		debug("line is not alnum\n");
		return -1;
	}

	if (dict == 0) {

		debug("not a valid dict pointer\n");
		return -1;
	}
	
	// check to see if the separator is even in the input line
	char *separator = strchr(line, delim);

	if (separator == 0) {

		debug("separator not found\n");
		return -1;
	}

	// insert a null at the separator position
	*separator = 0;

	debug("line = %s\n", line);

	// now walk backwards to remove any spaces between the end of the key and separator

	int i;

	for (i=strlen(line)-1; isblank(*(line+i)); --i ) {
		*(line+i) = 0;
		debug("line: %s  strlen(line) %ld\n", line, strlen(line));
	}

	// now walk the separator forward until the first non-space char
	++separator;


	while (*separator != 0 && isblank(*separator)) {

		++separator;
	}

	value = separator;

	while (*separator != 0 && *separator != '\r' && *separator != '\n')
		++separator;

	*separator = 0;

	debug("Key: %s, Value: %s\n", line, value);


	addDictEntry(dict, line, value);

	return 0;

}

char *findDict( dictionaryType *dict, char *key) {
	
dictionaryType *tempDict;

	if ( dict == 0) {

		return NULL;
	}

	tempDict = dict;

	while ((tempDict != 0) && strcmp( key, tempDict->key) != 0  ) {

		tempDict = tempDict->next;
	}

	if ( tempDict )
		return tempDict->value;
	else
		return NULL;

}


void deleteDict( dictionaryType **dict) {

	dictionaryType *tempDict;
	dictionaryType *nextEntry;

	if (*dict == 0)
		return;

	tempDict = *dict;

	// debug("tempDict = %p\n", tempDict);
	while (tempDict) {

		nextEntry = tempDict->next;
	// debug("tempDict = %p\n", tempDict);

		// debug("tempDict's key: %s\n", tempDict->key);
		free( tempDict->key);
		// debug("tempDict's value: %s\n", tempDict->value);
		free( tempDict->value);

		// debug("Freeing tempDict\n");
			// debug("tempDict = %p\n", tempDict);

		free( tempDict );

		tempDict = nextEntry;
	}

	*dict = 0;

	return;

}
