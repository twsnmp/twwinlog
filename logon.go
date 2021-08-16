package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// 誰がどのコンピュータにどこからログインしたか？
type logonEnt struct {
	//	ID          Target + Computer + IP
	Target      string
	Computer    string
	IP          string
	Count       int
	Logon       int
	Failed      int
	Logoff      int
	LogonTypes  map[string]int
	FailedCodes map[string]int
	FirstTime   int64
	LastTime    int64
}

func (e *logonEnt) String() string {
	logonTypes := ""
	for k, v := range e.LogonTypes {
		logonTypes += fmt.Sprintf(",logonType[%s]=%d", k, v)
	}
	failedCodes := ""
	for k, v := range e.FailedCodes {
		failedCodes += fmt.Sprintf(",failedCode[%s]=%d", k, v)
	}
	return fmt.Sprintf("type=Logon,target=%s,computer=%s,ip=%s,count=%d,logon=%d,failed=%d,logoff=%d%s%s,ft=%s,lt=%s",
		e.Target, e.Computer, e.IP, e.Count, e.Logon, e.Failed, e.Logoff,
		logonTypes, failedCodes,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var logonMap sync.Map

func updateLogon(s *System, l string, t time.Time) {
	logonType := getLogonType(getEventData(reLogonType, l))
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	targetUserName := getEventData(reTargetUserName, l)
	targetServerName := getEventData(reTargetServerName, l)
	targetUserSid := getEventData(reTargetUserSid, l)
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
	if s.EventID == 4648 {
		logonType = "Explicit"
	}
	ts := t.Unix()
	if s.EventID == 4625 {
		logonFailed++
		syslogCh <- &syslogEnt{
			Severity: 4,
			Time:     t,
			Msg: fmt.Sprintf("type=LogonFailed,subject=%s@%s,target=%s@%s,targetsid=%s,logonType=%s,ip=%s,code=%s,time=%s",
				subjectUserName, subjectDomainName, targetUserName, targetDomainName, targetUserSid, logonType, ipAddress, failedCode,
				t.Format(time.RFC3339),
			),
		}
	}
	if logonType == "Service" {
		// Skip Service Logon
		return
	}
	target := fmt.Sprintf("%s@%s", targetUserName, targetServerName)
	id := strings.ToUpper(target)
	if v, ok := logonMap.Load(id); ok {
		if e, ok := v.(*logonEnt); ok {
			incLogonEnt(e, s.EventID)
			if e.LastTime < ts {
				e.LastTime = ts
			}
			if failedCode != "" {
				e.FailedCodes[failedCode]++
			}
			if logonType != "" {
				e.LogonTypes[logonType]++
			}
		}
		return
	}
	e := &logonEnt{
		Count:       0,
		Target:      target,
		IP:          ipAddress,
		Computer:    s.Computer,
		FailedCodes: make(map[string]int),
		LogonTypes:  make(map[string]int),
		LastTime:    ts,
		FirstTime:   ts,
	}
	if failedCode != "" {
		e.FailedCodes[failedCode] = 1
	}
	if logonType != "" {
		e.LogonTypes[logonType] = 1
	}
	incLogonEnt(e, s.EventID)
	logonMap.Store(id, e)
}

func incLogonEnt(e *logonEnt, eventID int) {
	e.Count++
	switch eventID {
	case 4624, 4648:
		e.Logon++
	case 4625:
		e.Failed++
	case 4647, 4634:
		e.Logoff++
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

func sendLogon() {
	logonMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*logonEnt); ok {
			if debug {
				log.Printf("logon id=%s,e=%v", k, e)
			}
			logonCount++
			syslogCh <- &syslogEnt{
				Severity: 6,
				Time:     time.Now(),
				Msg:      e.String(),
			}
			logonMap.Delete(k)
		}
		return true
	})
}
