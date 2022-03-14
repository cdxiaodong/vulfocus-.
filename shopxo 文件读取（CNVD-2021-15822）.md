 shopxo 文件读取（CNVD-2021-15822）

打开网页

shopxo是一款开源的企业级商城系统，基于thinkphp5框架开发

尝试访问默认登陆后台，后台页面为/admin.php：

使用shopxo的默认账号密码进行登录：账号：admin 密码：shopxo
成功进入后台

![image-20211010193559231](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211010193559231.png)

在后台找到 应用中心-应用商店-主题，然后下载默认主题。

随便找一个免费的下载。下载下来的主题是一个zip安装包，然后把webshell放到压缩包的`default\_static_` 目录下

回到网页上，找到 网站管理-主题管理-主题安装（然后选择你加入webshell后的主题压缩包进行上传）

![image-20211010194715925](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211010194715925.png)

上传成功后，在当前主题中可以看到

![image-20211010194728503](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211010194728503.png)

这里查看主页上的当前主题就能知道文件的位置

![image-20211010194747780](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211010194747780.png)



蚁剑连接 ok

![image-20211010194941508](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211010194941508.png)

修复

更新到新版本

