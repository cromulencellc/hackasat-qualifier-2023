#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

bool quick_maths(uint32_t run);

int main() {
  puts("enter decimal number: ");

  uint32_t candidate;
  scanf("%d", &candidate);

  bool happy = quick_maths(candidate);

  if (! happy) {
    puts("hmm… not happy :(");
    exit(1);
  }

  puts("cool :)");
  return 0;
}
