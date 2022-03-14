seacms 远程命令执行 （CNVD-2020-22721）

描述: 海洋CMS一套程序自适应电脑、手机、平板、APP多个终端入口。 SeaCMS v10.1存在命令执行漏洞，在w1aqhp/admin_ip.php下第五行使用set参数，对用户输入没有进行任何处理，直接写入文件。攻击者可利用该漏洞执行恶意代码，获取服务器权限。 后台路径：/manager 后台密码：admin:admin

漏洞利用

打开网站

![image-20211009172445319](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009172445319.png)

/manager找到后台

![image-20211009172546170](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009172546170.png)

admin/admin输入密码



![image-20211009172621784](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009172621784.png)

漏洞位置在系统的图片水印设置里面

![image-20211009173055001](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009173055001.png)

随便提交一份图片抓包

![image-20211009174622272](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009174622272.png)

改包

![image-20211009174643272](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009174643272.png)

再去打开图片水印设置

![image-20211009174727359](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009174727359.png)

ok

输入ls/temp

![image-20211009174807949](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211009174807949.png)

