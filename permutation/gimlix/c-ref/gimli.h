#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include <stdint.h>

void gimli(uint32_t *state);
void gimlix(uint32_t *state);