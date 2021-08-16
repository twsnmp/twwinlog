package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type taskEnt struct {
	Subject   string
	Computer  string
	TaskName  string
	Count     int
	FirstTime int64
	LastTime  int64
	SendTime  int64
}

// <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data>
// <Data Name="SubjectUserName">dadmin</Data>
// <Data Name="SubjectDomainName">CONTOSO</Data>
// <Data Name="TaskName">\\Microsoft\\StartListener</Data>

func (e *taskEnt) String() string {
	return fmt.Sprintf("type=Task,subject=%s,taskname=%s,computer=%s,count=%d,ft=%s,lt=%s",
		e.Subject, e.TaskName, e.Computer, e.Count,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var taskMap sync.Map

func updateTask(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	taskName := getEventData(reTaskName, l)
	ts := t.Unix()
	id := strings.ToUpper(fmt.Sprintf("%s:%s", taskName, s.Computer))
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
		Count:     1,
		TaskName:  taskName,
		Computer:  s.Computer,
		Subject:   subject,
		LastTime:  ts,
		FirstTime: ts,
	}
	taskMap.Store(id, e)
}

func sendTask() {
	taskMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*taskEnt); ok {
			if debug {
				log.Printf("task id=%s,e=%v", k, e)
			}
			taskCount++
			syslogCh <- &syslogEnt{
				Severity: 6,
				Time:     time.Now(),
				Msg:      e.String(),
			}
			taskMap.Delete(k)
		}
		return true
	})
}
