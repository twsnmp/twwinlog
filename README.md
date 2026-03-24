# twwinlog
Windows event log sensor for TWSNMP FC

English | [日本語](./README_ja.md)

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

## Status

The trial version V1.0.0 has been released.(2021/8/8)
Log transmission improvement version V1.1.0 has been released.(2021/8/21)
V1.1.2 has been released.(2025/1/26)

## Build

do make to build

```
$make
```

You can specify the following targets.
```
  all        Build executable files (omitted)
  clean      Delete the builded executable file
  zip        Create Zip files for release
```

```
$make
```
Execute the executable file for Windows in the `dist` directory.

To create a zip file for distribution,
```
$make zip
```

Is executed.The zip file is created in the `dist/` directory.

## Run

### Usage

```
Usage of E:\twsnmpfc\twwinlog.exe:
  -auth string
        remote authentication:Default|Negotiate|Kerberos|NTLM
  -cpuprofile file
        write cpu profile to file
  -interval int
        syslog destination list (default "127.0.0.1:514")
        -interval int
        syslog send interval(sec) (default 300)
        -memprofile file
        write memory profile to file
        -mqtt string
        mqtt broker destination
        -mqttClientID string
        mqtt client id (default "twwinlog")
        -mqttPassword string
        mqtt password
        -mqttTopic string
        mqtt topic (default "twwinlog")
        -mqttUser string
        mqtt user name
        -password string
        remote user's password
        -remote string
        remote windows pc
        -syslog string
        syslog destination list
        -user string
        remote user name
```

| Parameters | Contents |
|---|---|
| Syslog | Syslog destination |
| Mqtt | MQTT broker destination |
| Interval | Check interval |
| Auth | Remote PC authentication method |
| User/Password | User name password for authentication of remote PC |
| Remote | Remote PC |

Syslog destinations can be specified multiple by separation of comma.
: You can also specify the port number.

```
-syslog 192.168.1.1,192.168.1.2:5514
```

### Start method

To start, you need a Syslog destination (-syslog).

You can start with the following command.

```
>twwinlog.exe  -syslog 192.168.1.1
```

To monitor remote PC event log

```
>twwinlog.exe  -syslog 192.168.1.1 -remote <PCのアドレス> -user <User> -password <Password>
```

## syslog message examle

The sentence of the transmitted syslog message is `local5`.TAG is `TwwinLog`.

This is an example of a log of the tallying by event ID.

```
type=EventID,computer=YMIRYZ,channel=System,provider=Microsoft-Windows-Dhcp-Client,eventID=50103,total=1,count=1,ft=2025-01-23T17:19:19+09:00,lt=2025-01-23T17:19:19+09:00
```

## TWSNMP FC Package

The TWWINLOG is included in the TWSNMP FC package.
Only Windows version.

For more information
https://note.com/twsnmp/n/nc6e49c284afb
Please see

## Copyright

see ./LICENSE

```
Copyright 2021-2025 Masayuki Yamai
```
