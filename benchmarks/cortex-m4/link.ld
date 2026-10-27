MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 4M
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}
SECTIONS
{
  .text : { KEEP(*(.isr_vector)) *(.text*) *(.rodata*) . = ALIGN(4); } > FLASH
  _sidata = LOADADDR(.data);
  .data : { . = ALIGN(4); _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > RAM AT> FLASH
  .bss  : { . = ALIGN(4); _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
  . = ALIGN(8);
  _end = .;
  PROVIDE(end = .);
  _estack = ORIGIN(RAM) + LENGTH(RAM) - 16;
  /* required by picolibc (sbrk); the benchmark never allocates */
  __heap_start = _end;
  __heap_end = _estack - 0x10000;
}
