# 安装xlinker到模拟器
# 自动启动xlinker到调试器
# 启动本地的调试器，并且与远程对接

rm xlinker
make xlinker DEBUG=1 XLINKER_VERSION=1 all
adb push ./xlinker.out /data/
adb push ./libhello.so /data
adb shell
