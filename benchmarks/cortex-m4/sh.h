#ifndef SH_H
#define SH_H
#include <stdint.h>
static inline int semi(int op, void *arg) {
  register int r0 __asm__("r0") = op;
  register void *r1 __asm__("r1") = arg;
  __asm__ volatile ("bkpt #0xAB" : "+r"(r0) : "r"(r1) : "memory");
  return r0;
}
static inline void sh_puts(const char *s) { semi(0x04, (void *)s); }
static inline void sh_exit(void) { uint32_t a[2] = {0x20026, 0}; semi(0x20, a); for(;;); }
static inline void sh_num(const char *t, uint32_t v) {
  char b[64]; int i = 0;
  while (*t) b[i++] = *t++;
  char d[24]; int n = 0;
  if (!v) d[n++] = '0';
  while (v) { d[n++] = '0' + (int)(v % 10u); v /= 10u; }
  while (n) b[i++] = d[--n];
  b[i++] = '\n'; b[i] = 0;
  sh_puts(b);
}
#endif
