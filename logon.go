//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"
)

// 誰がどのコンピュータにどこからログインしたか？

func checkLogon(s *System, l string, t time.Time) {
	logonType := getLogonType(getEventData(reLogonType, l))
	if logonType == "Service" {
		// Skip Service Logon
		return
	}
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	targetUserName := getEventData(reTargetUserName, l)
	targetServerName := getEventData(reTargetServerName, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	ipAddress := getEventData(reIpAddress, l)
	failedCode := getFailedCode(getEventData(reSubStatus, l))
	if targetServerName == "" {
		if targetDomainName != "" {
			targetServerName = targetDomainName
		} else {
			targetServerName = s.Computer
		}
	}
	if strings.Contains(strings.ToLower(targetServerName), "localhost") {
		targetServerName = s.Computer
	}
	target := fmt.Sprintf("%s@%s", targetUserName, targetServerName)
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	switch s.EventID {
	case 4625:
		logonFailedCount++
		syslogCh <- &syslogEnt{
			Severity: 3,
			Time:     t,
			Msg: fmt.Sprintf("type=LogonFailed,subject=%s,target=%s,computer=%s,ip=%s,logonType=%s,failedCode=%s,time=%s",
				subject, target, s.Computer, ipAddress, logonType, failedCode,
				t.Format(time.RFC3339),
			),
		}
	case 4647, 4634:
		logoffCount++
		syslogCh <- &syslogEnt{
			Severity: 6,
			Time:     t,
			Msg: fmt.Sprintf("type=Logoff,subject=%s,target=%s,computer=%s,ip=%s,logonType=%s,time=%s",
				subject, target, s.Computer, ipAddress, logonType,
				t.Format(time.RFC3339),
			),
		}
	case 4648:
		logonType = "Explicit"
		fallthrough
	default:
		logonCount++
		syslogCh <- &syslogEnt{
			Severity: 6,
			Time:     t,
			Msg: fmt.Sprintf("type=Logon,subject=%s,target=%s,computer=%s,ip=%s,logonType=%s,time=%s",
				subject, target, s.Computer, ipAddress, logonType,
				t.Format(time.RFC3339),
			),
		}
	}
}

func getFailedCode(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	switch c {
	case "", "0x0":
		return ""
	case "0xc0000064":
		return "UserNotFound"
	case "0xc000006a":
		return "BadPassword"
	case "0xc0000234":
		return "Locked"
	case "0xc0000072":
		return "Disabled"
	case "0xc000006f":
		return "Time"
	case "0xc0000070":
		return "Workstation"
	case "0xc0000071":
		return "ExpiredPassword"
	case "0xc0000193", "0xc00000193":
		return "ExpiredAccount"
	case "0xc0000133":
		return "ClockSync"
	case "0xc0000224":
		return "ChangePassword"
	case "0xc000015b":
		return "LogonType"
	}
	return "Unknown_" + c
}

func getLogonType(t string) string {
	t = strings.TrimSpace(t)
	switch t {
	case "":
		return ""
	case "2":
		return "Interactive"
	case "3":
		return "Network"
	case "4":
		return "Batch"
	case "5":
		return "Service"
	case "7":
		return "Unlock"
	case "8":
		return "IIS"
	case "10":
		return "Remote"
	case "11":
		return "Cached"
	}
	return "Unknown_" + t
}
