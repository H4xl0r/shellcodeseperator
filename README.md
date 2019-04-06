## obfuscating meterpreter reverse_tcp shellcode
混淆meterpretershellcode，当然别的也可以
## replace CODE variable with your own shellcode
把CODE变量替换成你的shellcode
## this script requires python3
python3运行很顺畅，没有错误，不知道别的怎样
## the main idea is to seperate the assembly code into small pieces in which case the antivirus software is unable to match any pattern as it remembered before
大体思路就是把汇编代码分隔开成为小的片段，来绕过杀软的特征码匹配
