#include <ps2emu/macros.h.S>
#include <ps2emu/symbols.h>

PS2EMU_FUNCTION(ps2emu_malloc, malloc_symbol)
PS2EMU_FUNCTION(ps2emu_free, free_symbol)

#ifdef zeroalloc_symbol
PS2EMU_FUNCTION(zeroalloc, zeroalloc_symbol)
#endif




