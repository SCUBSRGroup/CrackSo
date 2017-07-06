# MAKEFILE for linux GCC
#

# The version
VERSION=1.0

PLATFORM := $(shell uname | sed -e 's/_.*//')

# tools
ifndef COPY
COPY=cp
endif

ifndef RM
RM=rm
endif

ifndef MAKE
MAKE=make
endif

# NDK tools
SYSROOT := $(NDK_HOME)/platforms/android-8/arch-arm/
ADDR2LINE := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-addr2line
AR := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar
AS := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-as
CC := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gcc --sysroot=$(SYSROOT)
CXX := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-g++ --sysroot=$(SYSROOT)
GDB := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gdb
GDBTUI := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gdbtui
GPROF := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gprof
LD := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ld --sysroot=$(SYSROOT)
NM := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-nm
OBJCOPY := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-objcopy
OBJDUMP := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-objdump
RANLIB := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ranlib
READELF := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-readelf
RUN := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-run
SIZE := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-size
STRINGS := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-strings
STRIP := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-strip

# 打包选项
ARFLAGS := cr

# 开启调试选项
ifdef DEBUG
CFLAGS += -g3 -O0
CFLAGS += -DDEBUG
endif

# 是否使用地址无关代码
ifdef PIC
CFLAGS += -fpic
endif

# 是否要编译APP
ifdef APP
CFLAGS += -DAPP
ifdef PIC
CFLAGS += -fpie
endif
endif

OBJECTS=hello1.o hello2.o hello3.o
SOURCES=hello1.c hello2.c hello3.c
HEADERS=

# 这里有一个链接顺序的问题，必须首先链接.o文件以及.c文件x
# 随后才可以 链接.a文件，否则将找不到一些符号的定义
hello: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

libhello.a: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS)
	$(RANLIB) $@

libhello.so: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(CC) -shared -Wl,-init=my_init $(OBJECTS) $(LIBS) -o $@
# $(CC) -Wl,-init=my_init -shared $(OBJECTS) $(LIBS) -o $@

# libfuck.so: fuck.c
# 	$(CC) -shared fuck.c $(LIBS) -o $@

hello1.o: hello1.c
	$(CC) $(CFLAGS) -c $< -o $@

hello2.o: hello2.c
	$(CC) $(CFLAGS) -c $< -o $@

hello3.o: hello3.c
	$(CC) $(CFLAGS) -c $< -o $@

objdump: $(OBJDUMP)
	$(OBJDUMP) $(CMD)

objcopy: $(OBJCOPY)
	$(OBJCOPY) $(CMD)

readelf: $(READELF)
	$(READELF) $(CMD)

nm: $(NM)
	$(NM) $(CMD)

clean_local:
	-$(RM) -f *.o
	-$(RM) -f *.a
	-$(RM) -f hello

clean:
	-$(RM) -f `find . -type f | grep "[.]o" | xargs`
	-$(RM) -f `find . -type f | grep "[.]a" | xargs`
