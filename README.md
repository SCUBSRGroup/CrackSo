# CrackSo
**CrackSo**是一款通用化的脱壳工具，主要针对的仍是第2代壳(so本地加密型)
##0x01 Android SO壳的发展历程##
- 1)so本地加密，导入内存解密，壳加载器跑完不再做其他事情
- 2)程序正常运行时，壳可以重新接管控制权
- 3)vmp保护(第4代加壳)

##0x02 常见Android SO加壳思路##
- 1)破坏Elf Header:将Elf32_Ehdr 中的e_shoff, e_shnum, e_shstrndx, e_shentsize字段处理，变为无效值,导致IDA无法解析该SO文件
- 2)删除Section Header：在链接过程中，Section Header因没有用到，可随意删除，导致ida无法打开该so文件
- 3)有源码加密Section或者函数：（1）对section加壳 （2）对函数加壳
- 4)无源码加密Section或者函数： 将解密函数放在另一个so中，只需保证解密函数在被加密函数执行前执行即可。执行时机的选择：（1）在linker执行.init_array时（2）在OnLoad函数中。注意：解密so一定要放在被解密so后加载，否则，搜索进程空间找不到被解密的so
- 5)从内存加载SO（自定义loader加载）:详细参考：[SO文件格式及linker机制学习总结(1)](http://bbs.pediy.com/thread-197512.htm)，[SO文件格式及linker机制学习总结(2)](http://bbs.pediy.com/thread-197559.htm)。
- 6)packed SO(soinfo结构): 把loader的代码插入到原so的init_array或者jni_onload处，重打包成packed so，加载该so，首先执行init_array或者jni_onload，完成对原so的解密，从内存加载，形成soinfo结构，然后替换原packed so的soinfo结构
![](http://img.blog.csdn.net/20160924155433469?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)
- 7)llvm源码级混淆(Clang+LLVM):  [Clang](http://clang.llvm.org/)作为LLVM 的一个编译器前端，对源程序进行词法分析和语义分析，形成AST(抽象语法树) ,最后用[LLVM](http://llvm.org/)作为后端代码的生成器，详见：[Android LLVM-Obfuscator C/C++ 混淆编译的深入研究](http://blog.csdn.net/wangbaochu/article/details/45370543)
![](http://img.blog.csdn.net/20160924160335934?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)
- 8)花指令:在C语言中，内嵌arm汇编的方式，可加入arm花指令，迷惑IDA
- 9)so vmp保护:写一个ART虚拟执行so中被保护的代码，但在手机上效率是一个问题

##0x03 对应的脱壳思路##
- 1)破坏Elf Header和删除Section Header型：进行ELF section修复，详见：[ELF section修复的一些思考](http://bbs.pediy.com/thread-192874.htm)
- 2)有源码加密Section或者函数型：a)使用dlopen加载so，返回soinfo结构体 b)恢复原so,详见：[ELF section修复的一些思考](http://bbs.pediy.com/thread-192874.htm)  [从零打造简单的SODUMP工具](http://bbs.pediy.com/thread-194053.htm) 
- 3)无源码加密Section或者函数、内存加载SO型：和针对有源码加密Section或者函数类似，在ndk开发中调用dlopen即可。soinfo结构体恢复so文件时机：选择在Android源码中
- 4)so本地加密型：内存dump+重定位表、got表修复(大致流程：[头部修复]()→ [段地址修复]()→ [重定位节修复]()→ [重建节头]()→ [清除壳入口]() )

##0x04 Reference ##
- [1]SO文件格式及linker机制学习总结(1) [http://bbs.pediy.com/thread-197512.htm](http://bbs.pediy.com/thread-197512.htm)
- [2]SO文件格式及linker机制学习总结(2) [http://bbs.pediy.com/thread-197559.htm](http://bbs.pediy.com/thread-197559.htm)
- [3]ELF section修复的一些思考 [http://bbs.pediy.com/thread-192874.htm](http://bbs.pediy.com/thread-192874.htm)
- [4]从零打造简单的SODUMP工具 [http://bbs.pediy.com/thread-194053.htm](http://bbs.pediy.com/thread-194053.htm)
- [5]安卓so文件脱壳思路: [http://www.52pojie.cn/forum.php?mod=viewthread&tid=477496](http://www.52pojie.cn/forum.php?mod=viewthread&tid=477496)
- [6]12306之梆梆加固libsecexe.so的脱壳及修复: [http://blog.csdn.net/justfwd/article/details/50176705](http://blog.csdn.net/justfwd/article/details/50176705)
