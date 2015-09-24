#编译环境
Windows XP SP3 32bit

VC 6.0

#功能描述
打印 C:\Windows\System32\Notepad.exe 的PE文件头信息。

#遇到的问题：
一个结构体在定义的时候，可以直接在头部进行声明，然后在文件中进行定义。
在声明的时候不分配内存空间，所以也不用加EXTERN关键字。
