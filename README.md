# MicroChat 微信安卓通信协议学习

技术是无罪的，快乐就在思考
本代码和文章仅供参考微信通讯模型学习交流

> 声明

## 请勿用于商业用途及违法行为，否则后果自负！！！

已修复原贴无法编译和编译出错问题  一键直接编译， release里有编译好的项目


目前功能不是很完善，感谢原作者提供思路!    希望微信官方能够提供可二次开放的小程序/AppSDK接口！

本人能力有限，欢迎交流学习探讨！  如果产生侵权请联系我， 我会立即删除相关内容 ！

感谢原作者@InfiniteTsukuyomi提供的初始版代码   也感谢腾讯公司开源这套优秀的通信框架

> 参考

```

编译说明和微信协议分析：https://www.icefox.org/  (参考了很多文章)

微信旧版本逆向的源代码： https://github.com/h4dex/WeChatRE

腾讯微信MARS跨平台socket通信组件  https://github.com/Tencent/mars/   

文档：https://github.com/Tencent/mars/#mars_cn

SDK编译故障参考这里：https://github.com/Tencent/mars/tree/master/samples/Windows/

腾讯微信MARS跨平台socket通信组件  https://github.com/Tencent/Mars/simples

```

> 工具
```
Visual Studio 2015 及以上版本 (安装ATL及BOOST)
Wireshark
TCP dump
```

>部分帐号可能无法正常登录
 
```
请到 NetworkService::startTask 查看下请求和返回数据问题
群内部分成员测试已登录成功。

```


> 编译

```
需要设置 VC++目录

..\mars
..\mars\comm
..\mars\comm\windows
..\mars\openssl\include
..\mars\openssl\include\openssl
..\sqlite3
proto\protobuf


或填写附加包含目录

$(ProjectDir);$(ProjectDir)WTL;$(ProjectDir)../;$(ProjectDir)../mars;$(ProjectDir)../mars/comm/windows;$(ProjectDir)../mars/comm;$(ProjectDir)proto/protobuf


.\
```

关闭 SDL检查
关闭预编译头





> 原作者描述

# MicroChat
just for learning Duilib!

这套代码的价值取决于你的想象力.

群链接分享,抢红包,v1/v2/wxid数据采集，批量加好友，二进制硬件信息登录......

没有web协议功能的阉割，没有xp插件硬编码的hook,没有PC版需要扫码登录的限制,比多开模拟器按键精灵模拟操作更加效率.......


本项目仅用于Duilib学习交流，请勿用于非法用途.

python代码移至:https://github.com/InfiniteTsukuyomi/PyMicroChat
