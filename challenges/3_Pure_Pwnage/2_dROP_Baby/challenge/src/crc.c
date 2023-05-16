#include "debug.h"

/* Make the table for a fast CRC. */
void make_crc_table(unsigned long *crc_table)
{
  unsigned long c;
  int n, k;
  for (n = 0; n < 256; n++) {
    c = (unsigned long) n;
    for (k = 0; k < 8; k++) {
      if (c & 1) {
        c = 0xedb88320L ^ (c >> 1);
      } else {
        c = c >> 1;
      }
    }
    crc_table[n] = c;
  }
}

// for a new CRC value pass in a 0L as the first parameter
unsigned long crc32(unsigned long crc, unsigned char *buf, int len)  {

static int quick_table_done = 0;
static unsigned long crc_table[256];

unsigned long c = crc ^ 0xffffffffL;
  int n;

  if (!quick_table_done) {
    make_crc_table(crc_table);

      quick_table_done = 1;
  }

  for (n = 0; n < len; n++) {
    c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
  }
  return c ^ 0xffffffffL;
}

int check_message_crc(unsigned char *buffer, unsigned int length) {

	unsigned long calculated_crc;
	unsigned long sent_crc;

	calculated_crc = crc32(0L, buffer, length-sizeof(calculated_crc));
	sent_crc = *(unsigned long *)(buffer+length-sizeof(unsigned long));

	debug("calculated = %x, sent = %x\n", calculated_crc, sent_crc);

  if (calculated_crc != sent_crc) {

    return -1;
  }
  else {

    return 0;
  }
  
}