#编译环境
Windows XP SP3 32bit

VC 6.0

#功能描述

1、搜索区段的0区

2、向0区中添加ShellCode

3、计算E8 E9需要的相对地址

4、计算OEP

5、修改OEP

#修复的BUG

1、ImageBuffer转FileBuffer函数中，ImageBuffer和FileBuffer指针错位的问题

#遇到的问题：

1、在计算SHELLCODE 的 E8 E9地址时候，要计算他在真正执行的时候在虚拟4GB空间中的地址，言外之意，需要和ImageBase做运算。

2、在搜索区段的时候，只需要判断从开始地址到结束地址就好，不需要判断是否为最后一节。（相当于优化算法）

#小缺陷

这个程序只能在我本机上运行正确，因为MessageBoxA的地址是我在本机上算出来的。如果需要诸位的机器上运行正确，需要自己去填写自己机器的MessageBoxA地址。

在未来的日子中，我会放出修改了重定位表的代码。


