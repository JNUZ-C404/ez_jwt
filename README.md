# JWT Algorithm Bypass

**Author:** owpd

**Difficulty:** eazy

**Category:** Web

## 题目描述

小明写了一个简单的CMS用于测试JWT的安全性，他将算法设置为了HS256并设置了一个强大的密钥，他相信这样的布置已经天衣无缝了。但他的代码貌似有一些问题，你能绕过限制，获取到用户的隐私信息吗？

## 题目解析

注册用户并登录后抓包修改JWT中的alg参数为none,role参数为admin后，查看admin用户信息即可得到flag
