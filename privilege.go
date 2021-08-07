package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type privilegeEnt struct {
	Subject        string
	SubjectUserSid string
	Computer       string
	Count          int
	FirstTime      int64
	LastTime       int64
	SendTime       int64
}

func (e *privilegeEnt) String() string {
	return fmt.Sprintf("type=Privilege,subject=%s,subjectsid=%s,computer=%s,count=%d,ft=%s,lt=%s",
		e.Subject, e.SubjectUserSid, e.Computer, e.Count,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var privilegeMap sync.Map

func updatePrivilege(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectUserSid := getEventData(reSubjectUserSid, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	switch subjectUserName {
	case "LOCAL SERVICE", "SYSTEM":
		// Skip System
		return
	}
	ts := t.Unix()
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	if v, ok := privilegeMap.Load(subject); ok {
		if e, ok := v.(*logonEnt); ok {
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &privilegeEnt{
		Count:          1,
		Subject:        subject,
		SubjectUserSid: subjectUserSid,
		LastTime:       ts,
		FirstTime:      ts,
	}
	privilegeMap.Store(subject, e)
}

func sendPrivilege(rt int64) {
	privilegeMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*privilegeEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete logon=%s", k)
				privilegeMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				if debug {
					log.Printf("privilege id=%s,e=%v", k, e)
				}
				privilegeCount++
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
