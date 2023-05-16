#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define BUFFER_SIZE 200  

#define DEFAULT_TIMEOUT 10

#define SYNC1 0x41
#define SYNC2 0x43
#define SYNC3 0x45
#define SYNC4 0x47

#define IBI 0x4242
#define IBI_SIZE 20
#define FACE 0xcefa
#define FACE_SIZE 300
#define AA 0x4141
#define AA_SIZE 40

int do_aa();

int do_1b1();

int do_face();


int syncronize(int fd) {

	int state = 0;
	int char_count = 0;
	char c;

	while (1) {

		read(fd, &c, 1);

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

					// printf("got sync word\n");
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

		if (char_count > BUFFER_SIZE*2) {

			printf("unable to synchronize with incoming data\n");
			return -1;
		}

	}
}

int read_message(int fd) {

	unsigned short message_type;
	int retval;
	size_t count;

	count=read(fd, &message_type, sizeof(message_type));

	if (count < sizeof(message_type) ) {

		printf("unable to read bytes\n");
		return -1;
	}

	// printf("Message type = %x\n", message_type);

	switch(message_type) {

		case AA:

			retval = do_aa(fd);
			break;

		case IBI:

			retval = do_1b1(fd);
			break;

		case FACE:

			retval = do_face(fd);
			break;

		default:

			printf("bad message type received\n");
			retval = -1;


	} // switch

	return retval;
}

int do_aa(int fd) {

	unsigned char message_buffer[AA_SIZE];
	size_t count;

	count = read(fd, message_buffer, sizeof(message_buffer));

	if ( count < AA_SIZE) {

		printf("Message was too short\n");
		return -1;
	}
	return 0;
}

int do_1b1(int fd) {
	size_t count;
	unsigned char message_buffer[IBI_SIZE];

	// printf("what is an 1b1?\n");

	count = read(fd, message_buffer, IBI_SIZE*3);

	if ( count < IBI_SIZE) {

		printf("Message was too short\n");
		return -1;
	}

	return 0;
}

int do_face(int fd) {

	unsigned char message_buffer[FACE_SIZE];
	size_t count;

	// printf("face time\n");

	count = read(fd, message_buffer, sizeof(message_buffer));

	if ( count < FACE_SIZE) {

		printf("Message was too short\n");
		return -1;
	}

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

	setvbuf( stdin, NULL, _IONBF, 0 );
	setvbuf( stdout, NULL, _IONBF, 0 );

   	flag = getenv("FLAG");

    if (flag == NULL) {
        puts("No flag present");
        exit(-1);
    }

	fd = open("flag.txt", O_CREAT | O_WRONLY);

	if (fd < 0 ) {

		printf("Errno = %d trying to open flag.txt\n", errno);
		exit(-1);
	}

	fchmod(fd, S_IRUSR|S_IWUSR);

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

	printf("\nBaby's First RISC-V Stack Smash\n\n");
	printf("Because I like you (and this is a baby's first type chall) here is something useful: %p\n", &flag);
	printf("Exploit me!\n");

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

	while (1) {

		retval=syncronize(0);

		if (retval == -1) {

			printf("synchronizer failed after too many received bytes");
			return -1;
		}

		retval = read_message(0);

		if (retval == -1) {

			printf("did not read message\n");
			return -1;
		}

	}
	
} //main

