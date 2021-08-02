package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

var reLogonType = regexp.MustCompile(`<Data Name='LogonType'>(\d+)</Data>`)
var reSubjectUserName = regexp.MustCompile(`<Data Name='SubjectUserName'>([^<]+)</Data>`)
var reSubjectDomainName = regexp.MustCompile(`<Data Name='SubjectDomainName'>([^<]+)</Data>`)
var reTargetUserName = regexp.MustCompile(`<Data Name='TargetUserName'>([^<]+)</Data>`)
var reTargetDomainName = regexp.MustCompile(`<Data Name='TargetDomainName'>([^<]+)</Data>`)
var reIpAddress = regexp.MustCompile(`<Data Name='IpAddress'>([^<]+)</Data>`)
var reSubStatus = regexp.MustCompile(`<Data Name='SubStatus'>([^<]+)</Data>`)

// <Data Name='SubjectUserName'>DESKTOP-T6L1D1U$</Data>
// <Data Name='SubjectDomainName'>WORKGROUP</Data>
// <Data Name='TargetUserName'>SYSTEM</Data>
// <Data Name='TargetDomainName'>NT AUTHORITY</Data>
// <Data Name='IpAddress'>-</Data>
// <Data Name='SubStatus'>0xc0000064</Data>

type logonEnt struct {
	Target          string
	Computer        string
	Count           int
	Logon           int
	Failed          int
	Logoff          int
	ChangeSubject   int
	ChangeIP        int
	ChangeLogonType int
	LastSubject     string
	LastIP          string
	LastLogonType   string
	LastFailCode    string
	FirstTime       int64
	LastTime        int64
	SendTime        int64
}

func (e *logonEnt) String() string {
	return fmt.Sprintf("type=Logon,target=%s,count=%d,logon=%d,failed=%d,logoff=%d,changeSubject=%d,changeLogonType=%d,changeIP=%d,subject=%s,logonType=%s,ip=%s,failCode=%s,ft=%s,lt=%s",
		e.Target, e.Count, e.Logon, e.Failed, e.Logoff,
		e.ChangeSubject, e.ChangeLogonType, e.ChangeIP,
		e.LastSubject, e.LastLogonType, e.LastIP, e.LastFailCode,
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
	targetDomainName := getEventData(reTargetDomainName, l)
	ipAddress := getEventData(reIpAddress, l)
	failCode := getFailCode(getEventData(reSubStatus, l))
	if targetDomainName == "" {
		targetDomainName = s.Computer
	}
	ts := t.Unix()
	if s.EventID == 4625 {
		logonFailed++
		syslogCh <- &syslogEnt{
			Severity: 4,
			Time:     t,
			Msg: fmt.Sprintf("type=LogonFailed,subject=%s@%s,target=%s@%s,logonType=%s,ip=%s,code=%s,time=%s",
				subjectUserName, subjectDomainName, targetUserName, targetDomainName, logonType, ipAddress, failCode,
				t.Format(time.RFC3339),
			),
		}
	}
	if logonType == "Service" {
		// Skip Service Logon
		return
	}
	target := fmt.Sprintf("%s@%s", targetUserName, targetDomainName)
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	if v, ok := logonMap.Load(target); ok {
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
			if subject != e.LastSubject {
				e.ChangeSubject++
				e.LastSubject = subject
			}
			if failCode != "" {
				e.LastFailCode = failCode
			}
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &logonEnt{
		Count:         0,
		Target:        target,
		LastIP:        ipAddress,
		LastSubject:   subject,
		LastLogonType: logonType,
		LastFailCode:  failCode,
		LastTime:      ts,
		FirstTime:     ts,
	}
	incLogonEnt(e, s.EventID)
	logonMap.Store(target, e)
}

func incLogonEnt(e *logonEnt, eventID int) {
	e.Count++
	switch eventID {
	case 4624:
		e.Logon++
	case 4625:
		e.Failed++
	case 4647, 4634:
		e.Logoff++
	}
}

func getEventData(re *regexp.Regexp, l string) string {
	if a := re.FindAllStringSubmatch(l, 1); len(a) > 0 && len(a[0]) > 1 && a[0][1] != "-" {
		return a[0][1]
	}
	return ""
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

func sendLogonReport(st, rt int64) {
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
