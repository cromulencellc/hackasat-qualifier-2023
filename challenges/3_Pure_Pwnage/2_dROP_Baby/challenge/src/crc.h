#ifndef crc_h

#define crc_h

unsigned long crc32(unsigned long crc, unsigned char *buf, int len);
int check_message_crc(unsigned char *buffer, unsigned int length);


#endif
