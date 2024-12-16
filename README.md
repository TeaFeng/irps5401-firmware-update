本项目用于英飞凌IRPS5401电源芯片在线升级，代码框架基于AMI BMC。


主程序：

主程序位于update路径下，使用.bin文件进行升级。主升级程序留下了拓展支持其他类型电源芯片的余地，但目前并未增加具体的其他芯片的支持。
主程序需要通过其他方式调用最终的接口启动相关线程来进行升级，闭关通过全局变量来查询升级进度。
当前程序没有提供redfish接口或者对应的IPMI命令，需要使用者自行编写上层调用函数（也不难，对吧？）。

固件转换程序：

txt2bin_linux与txt2bin_win两个目录分别适用于linux与windows系统，用于将英飞凌原始的txt格式的固件转换为二进制.bin文件。
代码当前都只支持单镜像固件，不支持多镜像固件（.mic文件）。
txt2bin程序在linux下使用SHA256 + openssl 1.1.1版本进行签名，windows下使用SHA256 + openssl 3.4版本进行签名，因此编译这两个程序的host设备必须先安装这两个版本的openssl。
两程序均使用静态链接，编译后生成的可执行程序不依赖具体的环境运行。


Firmware updating program of Infineon power IC irps5401.
Also supply firmware transform program,which transform txt file to bin file.
