* 在命令行中逐行执行cmd.bat中的命令
* 目录下会生成a.xml文件
* 32位执行：C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe a.xml
* 64位执行：C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe a.xml
* 64位可能会出现内存读取异常错误，建议使用32位