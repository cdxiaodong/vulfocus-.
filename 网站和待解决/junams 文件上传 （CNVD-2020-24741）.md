 junams 文件上传 （CNVD-2020-24741）

描述: JunAMS是一款以ThinkPHP为框架的开源内容管理系统。 JunAMS内容管理系统存在文件上传漏洞，攻击者可利用该漏洞上传webshell，获取服务器权限。 后台路径 /admin.php admin:admin

漏洞利用：

找到上传点：

![image-20211023113558243](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211023113558243.png)

上传图片码

