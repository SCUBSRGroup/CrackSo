#
# Makefile - needs GNU make 3.81 or better
#
# Copyright (C) 2013-2014 4dog.cn
#

# 确定是否是正确的Make版本
ifneq ($(findstring $(firstword $(MAKE_VERSION)),3.77 3.78 3.78.1 3.79 3.79.1 3.80),)
$(error GNU make 3.81 or better is required)
endif

# 定义源目录,取最后一个make文件的,也就是当前处理的make文件的路径作为源目录
# sed的作用是如果文件名以$结尾,则去掉这个$号
ifndef srcdir
srcdir := $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))
srcdir := $(shell echo '$(srcdir)' | sed 's,/*$$,,')
endif

# 设定顶级目录
ifndef top_srcdir
top_srcdir := $(srcdir)/..
endif

# 如果源目录非当前目录则设定VPATH
ifneq ($(srcdir),.)
##$(info Info: using VPATH . $(srcdir))
VPATH := . $(srcdir)
endif

# 包含全局配置与本地配置脚本
include $(wildcard $(top_srcdir)/Makevars.global $(srcdir)/Makevars.local)

# -r(--no-builtin-rules)禁止make使用任何隐含规则
# -R(--no-builtin-variabes)禁止make使用任何作用于变量上的隐含规则
MAKEFLAGS += -rR
.SUFFIXES:
export SHELL = /bin/sh
# call函数的参数模板e
# $($1)负责展开选项
# $(EXTRA_$1)表示当前选项的扩展选项,例如:CXXFLAGS,则展开变量$(EXTRA_CXXFLAGS)
# $($(project)_$1)表示针对tdog的选项,例如:CXXFLAGS,则展开变量$(tdog_CXXFLAGS)
# $($(basename $(notdir $@)).$1) 表示针对某个文件的选项,例如:CXXFLAGS,$@=linker.cpp
# 则展开变量$(linker.CXXFLAGS)
# 针对几个层级进行编译或者链接或者其他操作的参数构造
override e = $($1) $(EXTRA_$1) $($(project)_$1) $($(basename $(notdir $@)).$1)

# 指定编译器
# ifeq ($(CXX),)
# CXX = g++
# endif

# 如果USE_GNUC之前定义过,则保持之前的值,否则则默认开启
# ifneq ($(findstring $(firstword $(CXX)),g++),)
# USE_GNUC ?= 1
# endif

# 如果USE_GNUC等于1则设定相应编译选项
ifeq ($(USE_GNUC),1)

# 调试编译
ifeq ($(DEBUG),1)
CXXFLAGS += -O0 -g3
else
CXXFLAGS += -O3
endif

# 体系架构
ifeq ($(ANDROID),)
# 在真实的机器下采用指定体系的编译选项
ifeq ($(ARCH),32)
CXXFLAGS += -m32
else
CXXFLAGS += -m64
endif
endif

endif

# 合成编译选项
CPPFLAGS += $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) # 生成依赖关系使用
CXXLD ?= $(CXX)

# 后缀选项
exeext ?= .out
libext ?= .a
objext ?= .o

# 文件集合
local_SOURCES := $(sort $(wildcard $(srcdir)/*.cpp))
local_OBJECTS := $(notdir $(local_SOURCES:.cpp=$(objext)))

# 目标
all: $(project)$(exeext) | .depend
.DELETE_ON_ERROR: $(project)$(exeext) $(local_OBJECTS) .depend   # 发生错误时删除

# 这里提供了外部控制的HOOK选项
# 通过project.out变量的值.PRE_LINK_STEP来进行控制
# 当链接完成后可由project.out变量.POST_LINK_STEP来进行控制
$(project)$(exeext): $(local_OBJECTS) $($(project)_DEPENDENCIES)
	$($(notdir $@).PRE_LINK_STEP)
	$(strip $(CXXLD) $(call e,CPPFLAGS) $(call e,CXXFLAGS) $(call e,LDFLAGS) -o $@ $(local_OBJECTS) $(global_OBJECTS) $(call e,LDADD) $(call e,LIBS))
	$($(notdir $@).POST_LINK_STEP)

%.o : %.cpp | .depend
	$(strip $(CXX) $(call e,CPPFLAGS) $(call e,CXXFLAGS) -o $@ -c $<)

# 生成依赖文件
.depend: $(sort $(wildcard $(srcdir)/*.cpp $(srcdir)/*.h)) $(MAKEFILE_LIST)
	@rm -f $@

# 如果是GNU编译器集合
# 从文件集合中取出.cpp文件依次进行编译,并将编译输出去掉首尾空格写入到.depend文件中
# 如果非GNU编译器单纯的创建一个.depend的文件
ifeq ($(USE_GNUC),1)
	@echo "Updating $@"
	@$(strip $(CXX) $(call e,CPPFLAGS) -MM) $(filter %.cpp,$^) > $@
else
	touch $@
endif

# 清除
mostlyclean clean distclean maintainer-clean:
	rm -f *.d *.map *.o *.obj *.res .depend $(project).exe $(project).out $(project).ttp $(project)$(exeext)

# 伪目标
.PHONY: all mostlyclean clean distclean maintainer-clean

ifeq ($(MAKECMDGOALS),mostlyclean)
else ifeq ($(MAKECMDGOALS),clean)
else ifeq ($(MAKECMDGOALS),distclean)
else ifeq ($(MAKECMDGOALS),maintainer-clean)
else
-include .depend
endif
