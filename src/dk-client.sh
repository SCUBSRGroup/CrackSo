#!/bin/bash

# 安装udog到模拟器
# 自动启动udog到调试器
# 启动本地的调试器，并且与远程对接
# 启动a-gdbtui

AGdbtui="a-gdbtui"
TP=1234
SymbolFile="~/workspace/udog/src/udog.out"
#BreakLine=3021

$AGdbtui
