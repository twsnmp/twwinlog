package main

import (
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"
)

var reNewProcessName = regexp.MustCompile(`<Data Name='NewProcessName'>([^<]+)</Data>`)
var reProcessName = regexp.MustCompile(`<Data Name='ProcessName'>([^<]+)</Data>`)
var reParentProcessName = regexp.MustCompile(`<Data Name='ParentProcessName'>([^<]+)</Data>`)
var reStatus = regexp.MustCompile(`<Data Name='Status'>([^<]+)</Data>`)

// <Data Name='SubjectUserName'>DESKTOP-T6L1D1U$</Data>
// <Data Name='SubjectDomainName'>WORKGROUP</Data>
// <Data Name='NewProcessName'>C:\Users\myamai\AppData\Local\Programs\Microsoft VS Code\Code.exe</Data>
// <Data Name='ParentProcessName'>C:\Users\myamai\AppData\Local\Programs\Microsoft VS Code\Code.exe</Data>
// <Data Name='Status'>0x0</Data>
// <Data Name='ProcessName'>C:\Windows\System32\RuntimeBroker.exe</Data>

type processEnt struct {
	Computer      string
	Process       string
	Count         int
	StartCount    int
	ExitCount     int
	ChangeSubject int
	ChangeStatus  int
	ChangeParent  int
	LastSubject   string
	LastStatus    string
	LastParent    string
	FirstTime     int64
	LastTime      int64
	SendTime      int64
}

func (e *processEnt) String() string {
	return fmt.Sprintf("type=Process,computer=%s,process=%s,count=%d,start=%d,exit=%d,changeSubject=%d,changeStatus=%d,changeParent=%d,subject=%s,status=%s,parent=%s,ft=%s,lt=%s",
		e.Computer, e.Process, e.Count, e.StartCount, e.ExitCount,
		e.ChangeSubject, e.ChangeStatus, e.ChangeParent,
		e.LastSubject, e.LastStatus, e.LastParent,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var processMap sync.Map

func updateProcess(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	process := ""
	parent := ""
	status := ""
	ts := t.Unix()
	switch s.EventID {
	case 4688:
		process = getEventData(reNewProcessName, l)
		parent = getEventData(reNewProcessName, l)
	case 4689:
		process = getEventData(reProcessName, l)
		status = getEventData(reStatus, l)
	default:
		return
	}
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	id := fmt.Sprintf("%s:%s", s.Computer, process)

	if v, ok := processMap.Load(id); ok {
		if e, ok := v.(*processEnt); ok {
			e.Count++
			if s.EventID == 4688 {
				// Start
				e.StartCount++
				if subject != e.LastSubject {
					e.ChangeSubject++
					e.LastSubject = subject
				}
			} else {
				e.ExitCount++
				if status != "" && status != e.LastStatus {
					e.LastStatus = status
					e.ChangeStatus++
				}
			}
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	if s.EventID != 4688 {
		return
	}
	e := &processEnt{
		Computer:    s.Computer,
		Process:     process,
		Count:       1,
		StartCount:  1,
		LastSubject: subject,
		LastParent:  parent,
		LastTime:    ts,
		FirstTime:   ts,
	}
	processMap.Store(id, e)
}

func sendProcess(rt int64) {
	processMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*processEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete logon=%s", k)
				logonMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				// if debug {
				// 	log.Printf("process id=%s,e=%v", k, e)
				// }
				processCount++
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
