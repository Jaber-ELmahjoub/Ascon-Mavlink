#include <stdint.h>
extern int main(void);
extern uint32_t _estack, _sdata, _edata, _sbss, _ebss, _sidata;
void Reset_Handler(void) {
    uint32_t *s = &_sidata, *d = &_sdata;
    while (d < &_edata) *d++ = *s++;          /* copy .data from flash  */
    for (d = &_sbss; d < &_ebss; ) *d++ = 0;  /* zero .bss              */
    main();
    for (;;);
}
void Default_Handler(void) { for (;;); }
__attribute__((section(".isr_vector"), used))
void (*const vtable[])(void) = {
    (void (*)(void)) &_estack, Reset_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, 0, 0, 0, 0, Default_Handler, Default_Handler, 0,
    Default_Handler, Default_Handler
};
