# wiresharkScripts
# wireshark lua 脚本示例
建议参考文章https://www.jianshu.com/p/357abb93af0a 学习基础知识
使用了某人员定位8100 udp端口数据进行解析存放到wireshark中解析
步骤：
1. 找到wireshark的init.lua脚本，在其中添加将要编写的脚本文件
如： 在 /Applications/Wireshark.app/Contents/Resources/share/wireshark/init.lua 文件末尾添加
   dofile("/Users/lidf/workspace/luaTest/hello/main.lua")

2. 编写main.lua脚本
3. wireshark 载入抓到的包example.pacg
4. 查看文件
