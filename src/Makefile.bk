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

CFLAGS += -DANDROID_ARM_LINKER

# 开启调试选项
ifdef DEBUG
CFLAGS += -g3 -O0
CFLAGS += -DLINKER_DEBUG=1 -DLOG_TO_STDOUT=1
else
CFLAGS += -DNODEBUG -DLINKER_DEBUG=0
CFLAGS += -O3
endif

# UDOG标识
CFLAGS += -DUDOG


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

CXXFLAGS = $(CFLAGS)

OBJECTS=linker.o \
	linker_environ.o \
	linker_format.o \
	linker_phdr.o \
	dlfcn.o \
	rt.o \
	options.o	

# debugger.o

SOURCES=linker.cpp \
	linker_environ.cpp \
	linker_format.cpp \
	linker_phdr.cpp \
	dlfcn.cpp \
	rt.cpp \
	options.cpp

HEADERS=linker.h \
	linker_debug.h \
	linker_format.h \
	linker_phdr.h \
	linker_environ.h

test_aux: test_aux.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

# 这里有一个链接顺序的问题，必须首先链接.o文件以及.c文件x
# 随后才可以 链接.a文件，否则将找不到一些符号的定义
# xlinker: $(OBJECTS) $(SOURCES) $(HEADERS)
# 	$(CXX) $(CXXFLAGS) $(OBJECTS) libsupc++.a -o $@

udog: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) libsupc++.a -o $@

linker.o: linker.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

linker_environ.o: linker_environ.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

linker_format.o: linker_format.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

dlfcn.o: dlfcn.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

options.o: options.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# debugger.o: debugger.cpp
# 	$(CXX) $(CXXFLAGS) -c $< -o $@

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
	-$(RM) -f xlinker

clean:
	-$(RM) -f `find . -type f | grep "[.]o" | xargs`
