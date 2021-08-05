package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type logonEnt struct {
	Target          string
	TargetSid       string
	Computer        string
	Count           int
	Logon           int
	Failed          int
	Logoff          int
	ChangeSubject   int
	ChangeIP        int
	ChangeLogonType int
	LastSubjectSid  string
	LastSubject     string
	LastIP          string
	LastLogonType   string
	LastFailCode    string
	FirstTime       int64
	LastTime        int64
	SendTime        int64
}

func (e *logonEnt) String() string {
	return fmt.Sprintf("type=Logon,target=%s,targetsid=%s,count=%d,logon=%d,failed=%d,logoff=%d,changeSubject=%d,changeLogonType=%d,changeIP=%d,subject=%s,subjectsid=%s,logonType=%s,ip=%s,failCode=%s,ft=%s,lt=%s",
		e.Target, e.TargetSid, e.Count, e.Logon, e.Failed, e.Logoff,
		e.ChangeSubject, e.ChangeLogonType, e.ChangeIP,
		e.LastSubject, e.LastSubjectSid, e.LastLogonType, e.LastIP, e.LastFailCode,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var logonMap sync.Map

func updateLogon(s *System, l string, t time.Time) {
	logonType := getLogonType(getEventData(reLogonType, l))
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectUserSid := getEventData(reSubjectUserSid, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	targetUserName := getEventData(reTargetUserName, l)
	targetServerName := getEventData(reTargetServerName, l)
	targetUserSid := getEventData(reTargetUserSid, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	ipAddress := getEventData(reIpAddress, l)
	failCode := getFailCode(getEventData(reSubStatus, l))
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
				subjectUserName, subjectDomainName, targetUserName, targetDomainName, targetUserSid, logonType, ipAddress, failCode,
				t.Format(time.RFC3339),
			),
		}
	}
	if logonType == "Service" {
		// Skip Service Logon
		return
	}
	id := strings.ToUpper(fmt.Sprintf("%s@%s", targetUserName, targetServerName))
	target := fmt.Sprintf("%s@%s", targetUserName, targetServerName)
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	if v, ok := logonMap.Load(id); ok {
		if e, ok := v.(*logonEnt); ok {
			incLogonEnt(e, s.EventID)
			if logonType != e.LastLogonType {
				e.LastLogonType = logonType
				e.ChangeLogonType++
			}
			if ipAddress != "" && ipAddress != e.LastIP {
				e.ChangeIP++
				e.LastIP = ipAddress
			}
			if subject != e.LastSubject || subjectUserSid != e.LastSubjectSid {
				e.ChangeSubject++
				e.LastSubject = subject
				e.LastSubjectSid = subjectUserSid
			}
			if failCode != "" && failCode != "0x0" {
				e.LastFailCode = failCode
			}
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &logonEnt{
		Count:          0,
		Target:         target,
		TargetSid:      targetUserSid,
		LastIP:         ipAddress,
		LastSubject:    subject,
		LastSubjectSid: subjectUserSid,
		LastLogonType:  logonType,
		LastFailCode:   failCode,
		LastTime:       ts,
		FirstTime:      ts,
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

func getFailCode(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	c = strings.ToLower(c)
	switch c {
	case "0xc0000064":
		return "User not Found"
	case "0xc000006a":
		return "Bad Password"
	case "0xc0000234":
		return "Locked"
	case "0xc0000072":
		return "Disabled"
	case "0xc000006f":
		return "Time"
	case "0xc0000070":
		return "Workstation"
	case "0xc0000071":
		return "Expired Password"
	case "0xc0000193", "0xc00000193":
		return "Expired Account"
	case "0xc0000133":
		return "Clock Sync"
	case "0xc0000224":
		return "Change Password"
	case "0xc000015b":
		return "Logon Type"
	}
	return "Unknown:" + c
}

func getLogonType(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	switch t {
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
	return "Unknown:" + t
}

func sendLogon(rt int64) {
	logonMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*logonEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete logon=%s", k)
				logonMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				if debug {
					log.Printf("logon id=%s,e=%v", k, e)
				}
				logonCount++
				syslogCh <- &syslogEnt{
					Severity: 6,
					Time:     time.Now(),
					Msg:      e.String(),
				}
				e.SendTime = time.Now().Unix()
			}
		}
		return true
	})
}
