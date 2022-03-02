# k8s-certs-generator

### 1. 初始化环境

```shell
poetry intall
```

### 2. 二进制文件生成命令

```shell
poetry add pyinstaller
pyinstaller --clean -F k8s-certs-generator.py
```

### 3. 源码初始化证书

```shell
poetry run python k8s-certs-generator.py
```

### 4. 二进制文件初始化证书

```shell
[root@k8s-master-01 ~]# ./k8s-certs-generator


+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  _  __ ___  ____     ____             _           ____                                 _
 | |/ /( _ )/ ___|   / ___| ___  _ __ | |_  ___   / ___|  ___  _ __    ___  _ __  __ _ | |_  ___   _ __
 | ' / / _ \___ \  | |    / _ \| '__|| __|/ __| | |  _  / _ \| '_ \  / _ \| '__|/ _` || __|/ _ \ | '__|
 | . \| (_) |___) | | |___|  __/| |   | |_ \__ \ | |_| ||  __/| | | ||  __/| |  | (_| || |_| (_) || |
 |_|\_\___/|____/   \____|\___||_|    \__||___/  \____| \___||_| |_| \___||_|   \__,_| \__|\___/ |_|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


请依次输入一下内容（使用默认值可以直接回车）：

> K8S配置文件根目录（/etc/kubernetes）：
> K8S Service子网CIDR（10.96.0.0/12）：
> 命令行打印日志Level（info）：
> 证书有效期（3650）：
> 证书专用信息-C（CN）：
> 证书专用信息-ST（shandong）：
> 证书专用信息-L（jinan）：
> 证书专用信息-O（personal）：
> 证书专用信息-OU（personal）：
> 证书专用信息-CN（local.com）：
> 请输入Master节点IP地址（必填）：192.168.1.11
> 请输入Master节点Hostname（必填）：k8s-master-01
> 是否继续添加Master节点（yes/no，默认no）：y
> 请输入Master节点IP地址（必填）：192.168.1.12
> 请输入Master节点Hostname（必填）：k8s-master-02
> 是否继续添加Master节点（yes/no，默认no）：yes
> 请输入Master节点IP地址（必填）：192.168.1.13
> 请输入Master节点Hostname（必填）：k8s-master-03
> 是否继续添加Master节点（yes/no，默认no）：
> 请输入Master节点对外服务内网地址（192.168.1.11）：
> 请输入Master节点对外服务外网地址（非必填）：
> 是否展示生成证书具体信息（yes/no，默认no）：y
> 是否开始生成证书（yes/no，默认yes）：



[2022-01-19 09:41:11,616] INFO 19712 k8s-certs-generator 202: | =====开始创建k8s通用CA证书=====
[2022-01-19 09:41:11,839] INFO 19712 k8s-certs-generator 715: | =====证书[/etc/kubernetes/pki/ca.crt]内容如下：=====
[2022-01-19 09:41:11,840] INFO 19712 k8s-certs-generator 716: | Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            96:9d:3d:08:4e:00:9a:ce
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=kubernetes-ca
        Validity
            Not Before: Jan 19 01:41:11 2022 GMT
            Not After : Jan  7 01:41:11 2032 GMT
        Subject: CN=kubernetes-ca
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:e7:7a:3f:f0:4e:34:d2:5e:d1:36:36:71:0b:19:
                    2b:0b:bf:18:89:75:55:60:63:76:7d:bf:02:c8:0a:
                    29:83:1f:76:a6:41:43:82:32:e2:6e:d0:e5:6a:41:
                    7a:20:55:a4:92:fc:1f:b9:2d:d3:11:31:e2:ce:99:
                    bc:9a:ef:cb:d7:85:d6:08:5d:9b:82:1f:14:e8:14:
                    c5:9c:fd:8e:49:ac:39:0d:f6:ca:13:e4:b2:ce:9f:
                    ad:71:a3:e6:ef:5b:3d:44:f9:42:42:fb:ed:d1:27:
                    5a:ea:4c:aa:76:83:06:6b:c5:37:f9:02:b0:22:77:
                    3d:7d:57:9c:fc:d3:9a:d3:06:41:42:26:d0:b0:3e:
                    2d:3e:9b:76:5a:f1:45:f8:52:5a:2a:c7:48:e3:71:
                    bf:fa:92:ea:83:cf:25:3c:91:8b:dd:b9:9c:7b:eb:
                    fb:b6:67:f8:fa:8c:8a:5f:18:4e:12:a1:3e:db:b4:
                    50:42:e5:88:40:6a:38:fb:cb:c8:9c:b6:6a:8a:4d:
                    41:81:af:33:9a:71:40:de:90:d4:48:59:e0:61:ee:
                    ed:3c:87:13:83:fd:e3:d1:3d:cb:d6:39:25:63:52:
                    96:ad:43:58:0a:7b:30:a4:c2:c3:00:46:c5:8a:43:
                    f4:7e:e5:6e:9a:f9:bf:39:f8:25:50:9c:08:85:b9:
                    ad:35
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                AF:E8:C1:2C:4A:1D:BA:69:F0:20:08:22:AB:57:CF:D8:F1:76:49:26
            X509v3 Authority Key Identifier:
                keyid:AF:E8:C1:2C:4A:1D:BA:69:F0:20:08:22:AB:57:CF:D8:F1:76:49:26

            X509v3 Basic Constraints:
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         a6:c6:95:ea:ef:11:98:82:3b:d1:30:fa:f8:89:3e:b5:51:39:
         b1:f2:fa:c0:31:e3:20:eb:f7:0a:f9:66:45:83:cd:69:0f:08:
         04:61:b7:79:c3:ff:09:69:8b:d0:c1:ad:09:52:2a:23:48:b9:
         2f:b9:b9:c5:22:0b:e3:48:44:6e:3f:3c:71:13:52:43:63:f2:
         ff:71:7e:e4:09:a3:12:fe:2b:0c:ed:01:30:83:fe:47:bd:43:
         a8:bf:81:a8:06:5d:02:26:f5:ad:ab:96:87:bf:4c:4a:31:c2:
         4c:e3:7d:0e:78:b6:cb:13:30:f9:fb:69:12:4f:42:05:2b:f8:
         d3:a6:c9:36:57:82:a7:78:09:45:c6:6e:41:e0:88:6a:5e:8b:
         92:a4:75:69:11:85:0b:9e:3f:25:a3:9c:33:85:a9:99:c1:55:
         06:64:d5:6f:6a:05:4f:52:1f:34:e4:83:cc:9f:5f:d0:a8:6e:
         fe:62:7d:49:01:a7:af:e6:6e:15:4a:0f:79:16:9f:b0:ec:a3:
         8b:93:89:a7:fd:82:76:a0:13:70:23:02:34:e3:c3:1d:c5:ce:
         e5:bf:2b:07:f1:d0:62:45:7b:64:bd:53:df:fd:4c:56:cc:12:
         8f:7c:ab:80:fa:57:c7:58:c0:68:a1:f4:12:7f:02:62:58:4f:
         32:f5:43:43

[2022-01-19 09:41:11,840] INFO 19712 k8s-certs-generator 204: | =====已创建k8s通用CA证书=====
......
```