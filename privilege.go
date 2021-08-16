package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type privilegeEnt struct {
	Subject   string
	Computer  string
	Count     int
	FirstTime int64
	LastTime  int64
}

func (e *privilegeEnt) String() string {
	return fmt.Sprintf("type=Privilege,subject=%s,computer=%s,count=%d,ft=%s,lt=%s",
		e.Subject, e.Computer, e.Count,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var privilegeMap sync.Map

func updatePrivilege(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	switch subjectUserName {
	case "LOCAL SERVICE", "SYSTEM":
		// Skip System
		return
	}
	ts := t.Unix()
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	if v, ok := privilegeMap.Load(subject); ok {
		if e, ok := v.(*privilegeEnt); ok {
			if e.LastTime < ts {
				e.LastTime = ts
			}
			e.Count++
		}
		return
	}
	e := &privilegeEnt{
		Count:     1,
		Subject:   subject,
		Computer:  s.Computer,
		LastTime:  ts,
		FirstTime: ts,
	}
	privilegeMap.Store(subject, e)
}

func sendPrivilege() {
	privilegeMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*privilegeEnt); ok {
			if debug {
				log.Printf("privilege id=%s,e=%v", k, e)
			}
			privilegeCount++
			syslogCh <- &syslogEnt{
				Severity: 6,
				Time:     time.Now(),
				Msg:      e.String(),
			}
			privilegeMap.Delete(k)
		}
		return true
	})
}
