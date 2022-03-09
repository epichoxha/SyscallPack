CFLAGS := -Os -s
CXXFLAGS += -w
COMPILED := compiled
CC_x64 := x86_64-w64-mingw32-gcc
STR_x64 := x86_64-w64-mingw32-strip
CC_x86 := i686-w64-mingw32-gcc
STR_x86 := i686-w64-mingw32-strip
LD_x64 := x86_64-w64-mingw32-ld
LD_x86 := i686-w64-mingw32-ld
RM := rm

all: unhook-bof unhook-pic

unhook-bof:
	$(CC_x64) -o $(COMPILED)/unhook-bof.x64.o -c unhook-bof.c
	$(CC_x86) -o $(COMPILED)/unhook-bof.x86.o -c unhook-bof.c

unhook-pic:
	nasm -f win64 lib/adjuststackx64.asm -o $(COMPILED)/adjuststackx64.o
	$(CC_x64) unhook-pic.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o $(COMPILED)/unhook-picx64.o -Wl, -Tlib/linker.ld,--no-seh
	$(LD_x64) -s $(COMPILED)/adjuststackx64.o $(COMPILED)/unhook-picx64.o -o $(COMPILED)/unhook-picx64.exe

clean:
	$(RM) $(COMPILED)/*.o
