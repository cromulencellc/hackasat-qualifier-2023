#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include "config.h"
#include "dictionary.h"
#include "debug.h"
#include "crc.h"

#define DEFAULT_TIMEOUT 10
#define MAX_BUFFER 100
#define MAX_FLAG_SIZE 200

#define SYNC1 0xde
#define SYNC2 0xad
#define SYNC3 0xbe
#define SYNC4 0xef

dictionaryType *configDict;
char flag[MAX_FLAG_SIZE];

int do_a1();
int do_b1();
int do_a2();
int do_b2();


int syncronize() {

	int state = 0;
	int char_count = 0;
	int count;
	char c;

	while (1) {

		count=read(0, &c, 1);

		if (count < 1) {

			return -1;
		}

		++char_count;

		switch(state) {

			case 0:

				if (c == SYNC1) {

					state = 1;
				}
				break;

			case 1:

				if (c == SYNC2) {

					state = 2;
				}
				else if (c == SYNC1) {

					state = 1;
				}
				else {

					state = 0;
				}

				break;

			case 2:

				if (c == SYNC3) {

					state = 3;
				}
				else if (c == SYNC1) {

					state = 1;
				}
				else {

					state = 0;
				}
				break;

			case 3:

				if (c== SYNC4) {

					debug("found sync\n");
					return 0;
				}
				else if (c == SYNC1) {

					state = 1;
				}
				else {

					state = 0;
				}
				break;

			default:

				break;
		}

		if (char_count > MAX_BUFFER*2) {

			debug("unable to synchronize with incoming data\n");
			return -1;
		}

	}
}

int read_message() {

	unsigned char message_type;
	unsigned int message_size;
	int retval;
	size_t count;

	count=read(0, &message_type, sizeof(message_type));

	if (count != sizeof(message_type) ) {

		debug("unable to read bytes\n");
		return -1;
	}

	debug("message_type = %x\n", message_type);

	switch(message_type) {

		case 0xa1:

			message_size = atoi(findDict(configDict, "A1_MSG_LEN"));

			debug("message_size = %u\n", message_size);
			retval = do_a1(message_size);
			break;

		case 0xa2:
			message_size = atoi(findDict(configDict, "A2_MSG_LEN"));
			debug("message_size = %u\n", message_size);

			retval = do_a2(message_size);
			break;

		case 0xb1:
			message_size = atoi(findDict(configDict, "B1_MSG_LEN"));
			debug("message_size = %u\n", message_size);

			retval = do_b1(message_size);
			break;

		case 0xb2:
			message_size = atoi(findDict(configDict, "B2_MSG_LEN"));
			debug("message_size = %u\n", message_size);

			retval = do_b2(message_size);
			break;
		default:

			debug("bad message type received\n");
			retval = -1;

	} // switch

	return retval;
}

int do_a1(unsigned int size) {

	unsigned char message_buffer[MAX_BUFFER];
	size_t count;

	count = read(0, message_buffer, size);

	if ( count < size) {

		debug("Message was too short\n");
		return -1;
	}

	if (check_message_crc(message_buffer, size) == -1)
		return -1;

	// debug("a1 message was good\n");

	return 0;
}

int do_a2(unsigned int size) {
	size_t count;
	unsigned char message_buffer[MAX_BUFFER];

	count = read(0, message_buffer, size);

	if ( count < size) {

		debug("Message was too short\n");
		return -1;
	}

	if (check_message_crc(message_buffer, size) == -1)
		return -1;

	// debug("a2 message was good\n");

	message_buffer[size-sizeof(size)] = NULL;

	addDictEntry(&configDict, "USER_DATA", message_buffer);

	return 0;
}

int do_b1(unsigned int size) {

	unsigned char message_buffer[MAX_BUFFER];
	size_t count;

	count = read(0, message_buffer, size);

	if ( count < size) {

		debug("Message was too short\n");
		return -1;
	}

	if (check_message_crc(message_buffer, size) == -1)
		return -1;

	// debug("b1 message was good\n");

	printDict(configDict);

	return 0;
}

int do_b2(unsigned int size) {

	unsigned char message_buffer[MAX_BUFFER];
	size_t count;

	count = read(0, message_buffer, size);

	if ( count < size) {
		debug("Message was too short\n");

		return -1;
	}

	if (check_message_crc(message_buffer, size) == -1)
		return -1;


	// debug("b2 message was good\n");

	return 0;
}


void alarm_handler(int sig) {
    puts("Time's up!");
    exit(1);
}


int main(int argc, char **argv) 
{
int retval;
int fd;
int i;
char *flag;

    setvbuf( stdout, NULL, _IONBF, 0 );

   	flag = getenv("FLAG");

    if (flag == NULL) {
        puts("No flag present");
        exit(-1);
    }

	fd = open("flag.txt", O_CREAT | O_WRONLY, S_IRUSR|S_IWUSR);

	if (fd < 0 ) {

		printf("Errno = %d trying to open flag.txt\n", errno);
		exit(-1);
	}

	// fchmod(fd, S_IRUSR|S_IWUSR);

	retval=write(fd, flag, strlen(flag));

	if (retval != strlen(flag)) {

		printf("Unable to write flag to file\n");
		exit(-1);
	}

	close(fd);
	
	retval=unsetenv("FLAG");

	if (retval == -1) {

		printf("Unable to clear environment\n");
		exit(-1);
	}

	char *timeout_str;
	unsigned int timeout;

    // set timeout from environment
    timeout_str = getenv("TIMEOUT");

    if (timeout_str != NULL) {

        timeout = strtoul(timeout_str, 0, 10);
        if (timeout == 0) {
            timeout = DEFAULT_TIMEOUT;
        }

    } else {
        timeout = DEFAULT_TIMEOUT;

    }

    // set alarm
    signal(SIGALRM, alarm_handler);
    alarm(timeout);

	printf("\nBaby's Second RISC-V Stack Smash\n\n");
	printf("No free pointers this time and pwning might be more difficult!\n");
	printf("Exploit me!\n");

	configDict = loadINI("server.ini");

	debug("loaded dictionary\n");

	if (configDict == NULL) {

		debug("Error loading configuration from file\n");
		exit(-1);
	}

	while (1) {

		retval=syncronize();

		if (retval == -1) {

			debug("synchronizer failed after too many received bytes");
			return -1;
		}

		retval = read_message();

		if (retval == -1) {

			debug("did not read message\n");

			return -1;
		}

	}
	
} //main

