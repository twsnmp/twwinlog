# twwinlog
Windows event log sensor for TWSNMP
TWSNMPのためのWindowsイベントログセンサー

[![Godoc Reference](https://godoc.org/github.com/twsnmp/twwinlog?status.svg)](http://godoc.org/github.com/twsnmp/twwinlog)
[![Go Report Card](https://goreportcard.com/badge/twsnmp/twwinlog)](https://goreportcard.com/report/twsnmp/twwinlog)

## Overview

Windowsのイベントログを監視してTWSNMPで監視するために必要な情報をsyslogで送信するためのセンサープログラムです。
現在のバージョンでは以下の情報を取得できます。

- イベント数の集計
- イベントID別の集計
- ログオンに関する情報
- ログオン失敗の通知

## Status

開発を開始したばかりです。

## Build

ビルドはmakeで行います。
```
$make
```
以下のターゲットが指定できます。
```
  all        実行ファイルのビルド（省略可能）
  clean      ビルドした実行ファイルの削除
  zip        リリース用のZIPファイルを作成
```

```
$make
```
を実行すればWindows用の実行ファイルが、`dist`のディレクトリに作成されます。


配布用のZIPファイルを作成するためには、
```
$make zip
```
を実行します。ZIPファイルが`dist/`ディレクトリに作成されます。

## Run

### 使用方法

```
Usage of E:\twsnmpfc\twwinlog.exe:
  -auth string
        remote authentication:Default|Negotiate|Kerberos|NTLM
  -cpuprofile file
        write cpu profile to file
  -interval int
        syslog send interval(sec) (default 300)
  -memprofile file
        write memory profile to file
  -password string
        remote user's password
  -remote string
        remote windows pc
  -retention int
        data retention time(sec) (default 604800)
  -syslog string
        syslog destnation list
  -user string
        remote user name
```

syslogの送信先はカンマ区切りで複数指定できます。:に続けてポート番号を
指定することもできます。

```
-syslog 192.168.1.1,192.168.1.2:5514
```


### 起動方法

起動するためにはsyslogの送信先(-syslog)が必要です。

以下のコマンドで起動できます。

```
>twpcap.exe  -syslog 192.168.1.1
```


## Copyright

see ./LICENSE

```
Copyright 2021 Masayuki Yamai
```
