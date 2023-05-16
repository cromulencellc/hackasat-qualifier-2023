#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

bool quick_maths(double run);

int main() {
  puts("enter decimal number: ");

  double candidate;
  scanf("%lf", &candidate);

  bool happy = quick_maths(candidate);

  if (! happy) {
    puts("hmm… not happy :(");
    exit(1);
  }

  puts("cool :)");
  exit(0);
}
