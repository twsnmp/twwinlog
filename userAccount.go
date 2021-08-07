package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type userAccountEnt struct {
	Target         string
	TargetSid      string
	Computer       string
	Count          int
	Edit           int
	Other          int
	Password       int
	ChangeSubject  int
	LastSubjectSid string
	LastSubject    string
	FirstTime      int64
	LastTime       int64
	SendTime       int64
}

func (e *userAccountEnt) String() string {
	return fmt.Sprintf("type=Account,target=%s,targetsid=%s,computer=%s,count=%d,edit=%d,password=%d,other=%d,changesubject=%d,subject=%s,sbjectsid=%s,ft=%s,lt=%s",
		e.Target, e.TargetSid, e.Computer, e.Count, e.Edit, e.Password, e.Other,
		e.ChangeSubject,
		e.LastSubject, e.LastSubjectSid,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var userAccountMap sync.Map

func updateUserAccount(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectUserSid := getEventData(reSubjectUserSid, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	targetUserName := getEventData(reTargetUserName, l)
	targetUserSid := getEventData(reTargetUserSid, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	ts := t.Unix()
	id := strings.ToUpper(fmt.Sprintf("%s@%s", targetUserSid, s.Computer))
	target := fmt.Sprintf("%s@%s", targetUserName, targetDomainName)
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	if v, ok := userAccountMap.Load(id); ok {
		if e, ok := v.(*userAccountEnt); ok {
			incUserAcountEnt(e, s.EventID)
			if subject != e.LastSubject || subjectUserSid != e.LastSubjectSid {
				e.ChangeSubject++
				e.LastSubject = subject
				e.LastSubjectSid = subjectUserSid
			}
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &userAccountEnt{
		Count:          0,
		Target:         target,
		TargetSid:      targetUserSid,
		LastSubject:    subject,
		LastSubjectSid: subjectUserSid,
		LastTime:       ts,
		FirstTime:      ts,
	}
	incUserAcountEnt(e, s.EventID)
	userAccountMap.Store(id, e)
}

func incUserAcountEnt(e *userAccountEnt, eventID int) {
	e.Count++
	switch eventID {
	case 4720, 4726, 4738, 4781:
		e.Edit++
	case 723, 4724:
		e.Password++
	default:
		e.Other++
	}
}

func sendUserAccount(rt int64) {
	userAccountMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*userAccountEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete account=%s", k)
				userAccountMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				if debug {
					log.Printf("account id=%s,e=%v", k, e)
				}
				accountCount++
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
