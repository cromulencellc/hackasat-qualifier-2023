#include <stdint.h>
#include <stdbool.h>

bool quick_maths(uint32_t run) {
run = run + 11707;
run = run / 11;
run = run + 10926;
run = run + 118;
run = run * 13;
run = run + 2583;
run = run / 3;
run = run + 9679;
run = run * 22;
run = run + 9844;
run = run - 217;
run = run + 16333;
run = run + 10607;
run = run - 53;
run = run - 96;
run = run - 177;
return (run == 3633095605);
}
