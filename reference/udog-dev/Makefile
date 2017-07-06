#
# Makefile - needs GNU make 3.81 or better
#
# Copyright (C) 2013-2014 4dog.cn
#

MAKEFLAGS += -rR
.SUFFIXES:
export SHELL = /bin/sh

ifneq ($(findstring $(firstword $(MAKE_VERSION)),3.77 3.78 3.78.1 3.79 3.79.1 3.80),)
$(error GNU make 3.81 or better is required)
endif

# srcdir = .
# top_srcdir = .
# include $(wildcard $(top_srcdir)/Makevars.global ./Makevars.local)

default:
	@echo "[info]: please choose a target for 'make'"

all mostlyclean clean distclean maintainer-clean:
	$(MAKE) -C src $@

# 编译文档
ifneq ($(BUILD_DOC),)
	$(MAKE) -C doc $@
endif

.PHONY: default all mostlyclean clean distclean maintainer-clean
