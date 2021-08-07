package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type taskEnt struct {
	Subject        string
	SubjectUserSid string
	TaskName       string
	Computer       string
	Count          int
	FirstTime      int64
	LastTime       int64
	SendTime       int64
}

// <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data>
// <Data Name="SubjectUserName">dadmin</Data>
// <Data Name="SubjectDomainName">CONTOSO</Data>
// <Data Name="TaskName">\\Microsoft\\StartListener</Data>

func (e *taskEnt) String() string {
	return fmt.Sprintf("type=Task,taskname=%s,computer=%s,subject=%s,subjectsid=%s,count=%d,ft=%s,lt=%s",
		e.TaskName, e.Computer, e.Subject, e.SubjectUserSid, e.Count,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var taskMap sync.Map

func updateTask(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectUserSid := getEventData(reSubjectUserSid, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	taskName := getEventData(reTaskName, l)
	ts := t.Unix()
	id := strings.ToUpper(fmt.Sprintf("%s@%s", taskName, s.Computer))
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	if v, ok := taskMap.Load(id); ok {
		if e, ok := v.(*taskEnt); ok {
			e.Count++
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &taskEnt{
		Count:          1,
		Subject:        subject,
		TaskName:       taskName,
		Computer:       s.Computer,
		SubjectUserSid: subjectUserSid,
		LastTime:       ts,
		FirstTime:      ts,
	}
	log.Printf("task=%v", e)
	taskMap.Store(id, e)
}

func sendTask(rt int64) {
	taskMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*taskEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete logon=%s", k)
				taskMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				if debug {
					log.Printf("task id=%s,e=%v", k, e)
				}
				taskCount++
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
