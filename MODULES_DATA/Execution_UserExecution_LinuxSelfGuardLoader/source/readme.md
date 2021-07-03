# 注意事项

Viper默认的glibc版本为GLIBC 2.5,所以编译出的elf文件也依赖glic 2.5,如果目标linux的glibc版本低于2.5(极少),elf文件会执行失败.

请按照如下方法自行编译elf:

- 目标机执行```ldd --version```查看glibc版本
- 搭建对应glibc版本的linux环境
- 安装gcc
- ```gcc main.c -o payload.elf -static -z execstack```(x64)编译源码
- ```gcc -m32 main.c -o payload.elf -static -z execstack```(x86)编译源码
- 将payload.elf上传到目标机执行
