# wiresharkScripts
# wireshark lua 脚本示例

建议参考文章 https://www.jianshu.com/p/357abb93af0a 学习基础知识

lua 语法参考 http://www.lua.org/manual/5.4/manual.html#6.4

使用了某人员定位8100 udp端口数据进行解析存放到wireshark中解析

步骤：
1. 找到wireshark的init.lua脚本，在其中添加将要编写的脚本文件<br/>
   如： 在 /Applications/Wireshark.app/Contents/Resources/share/wireshark/init.lua 文件末尾添加<br/>
   dofile("/Users/lidf/workspace/luaTest/hello/main.lua")<br/>
2. 编写main.lua脚本
3. wireshark 载入抓到的包example.pacg
4. 查看文件
