# twwinlog
Windows event log sensor for TWSNMP FC  
TWSNMP FCのためのWindowsイベントログセンサー

[![Godoc Reference](https://godoc.org/github.com/twsnmp/twwinlog?status.svg)](http://godoc.org/github.com/twsnmp/twwinlog)
[![Go Report Card](https://goreportcard.com/badge/twsnmp/twwinlog)](https://goreportcard.com/report/twsnmp/twwinlog)

## Overview

A sensor program for sending Windows event logs to TWSNMP FC by syslog.
You can get the following information in the current version.

-Trimed the number of events
-The aggregation by event ID
-Progion information (4624, 4625, 4648, 4634, 4647)
-Information about changing accounts
(4720,4722,4723,4724,4726,4738,4740,4767,4781)
-Procompate access information (4672,4673)
-Prot information about Kerberos authentication (4768,4769)
-Information about the schedule task (4698)
-Information about the process start and stop (4688, 4689)
-Notification of logon failure (4625)
-Kerberos Notification of Ticket Requests Failure (4768,4769)
-Proll notification of event log erasing (1102)

WindowsのイベントログをTWSNMP FCにsyslogで送信するためのセンサープログラムです。  
現在のバージョンでは以下の情報を取得できます。

- イベント数の集計
- イベントID別の集計
- ログオンに関する情報(4624, 4625, 4648, 4634, 4647)
- アカウントの変更に関する情報  
   (4720,4722,4723,4724,4725,4726,4738,4740,4767,4781)
- 特権アクセスに関する情報(4672,4673)
- Kerberos認証に関する情報(4768,4769)
- スケジュールタスクに関する情報(4698)
- プロセスの起動、停止に関する情報(4688, 4689)
- ログオン失敗の通知(4625)
- Kerberosチケット要求失敗の通知(4768,4769)
- イベントログ消去の通知(1102)

## Status

The trial version V1.0.0 has been released.(2021/8/8)
Log transmission improvement version V1.1.0 has been released.(2021/8/21)
V1.1.2 has been released.(2025/1/26)

お試し版v1.0.0をリリースしました。(2021/8/8)  
ログ送信改善版v1.1.0をリリースしました。(2021/8/21)  
v1.1.2をリリースしました。(2025/1/26)  

## Build

do make to build

ビルドはmakeで行います。

```
$make
```

You can specify the following targets.
```
  all        Build executable files (omitted)
  clean      Delete the builded executable file
  zip        Create Zip files for release
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

```
$make
```
Execute the executable file for Windows in the `Dist` directory.


To create a zip file for distribution,
```
$make zip
```

Is executed.The zip file is created in the `dist/` directory.

配布用のZIPファイルを作成するためには、
```
$make zip
```
を実行します。ZIPファイルが`dist/`ディレクトリに作成されます。

## Run

### Usage

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
  -syslog string
        syslog destnation list
  -user string
        remote user name
```


| Parameters | Contents |
|---|---|
| Syslog | Syslog destination |
| Interval | Check interval |
| Auth | Remote PC authentication method |
| User/Password | User name password for authentication of remote PC |
| Remoe | Report PC |

|パラメータ|内容|
|---|---|
|syslog|syslogの送信先|
|interval|チェック間隔|
|auth|リモートPCの認証方法|
|user/password|リモートPCの認証時のユーザー名パスワード|
|remoe|リポートPC|


Syslog destinations can be specified multiple by separation of comma.
: You can also specify the port number.

syslogの送信先はカンマ区切りで複数指定できます。
:に続けてポート番号を指定することもできます。

```
-syslog 192.168.1.1,192.168.1.2:5514
```


### Start method

To start, you need a Syslog destination (-sySlog).

起動するためにはsyslogの送信先(-syslog)が必要です。

You can start with the following command.

以下のコマンドで起動できます。

```
>twwinlog.exe  -syslog 192.168.1.1
```

To monitor remote PC event log

別のPCのイベントログをモニタするためには、

```
>twwinlog.exe  -syslog 192.168.1.1 -remote <PCのアドレス> -user <User> -password <Password>
```

## syslog message examle

The sentence of the transmitted syslog message is `local5`.TAG is `TwwinLog`.

送信されるsyslogのメッセージのファシリティーは`local5`です。tagは`twwinlog`です。

This is an example of a log of the tallying by event ID.

イベントID別の集計のログの例です。

```
type=EventID,computer=YMIRYZ,channel=System,provider=Microsoft-Windows-Dhcp-Client,eventID=50103,total=1,count=1,ft=2025-01-23T17:19:19+09:00,lt=2025-01-23T17:19:19+09:00
```


## TWSNMP FC Package

The TWWINLOG is included in the TWSNMP FC package.
Only Windows version.

TWSNMP FCのパッケージにtwWinlogが含まれています。  
Windows版のみです。

For more information
https://note.com/twsnmp/n/nc6e49c284afb
Please see

詳しくは、  
https://note.com/twsnmp/n/nc6e49c284afb  
を見てください。


## Copyright

see ./LICENSE

```
Copyright 2021-2025 Masayuki Yamai
```
