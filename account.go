package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// 誰がどのアカウントを変更したか？
type AccountEnt struct {
	// ID = Target + Subject + Computer
	Target    string
	Subject   string
	Computer  string
	Count     int
	Edit      int
	Other     int
	Password  int
	FirstTime int64
	LastTime  int64
}

func (e *AccountEnt) String() string {
	return fmt.Sprintf("type=Account,subject=%s,target=%s,computer=%s,count=%d,edit=%d,password=%d,other=%d,ft=%s,lt=%s",
		e.Subject, e.Target, e.Computer, e.Count, e.Edit, e.Password, e.Other,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var AccountMap sync.Map

func updateAccount(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	targetUserName := getEventData(reTargetUserName, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	ts := t.Unix()
	target := fmt.Sprintf("%s@%s", targetUserName, targetDomainName)
	subject := fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName)
	id := strings.ToUpper(fmt.Sprintf("%s:%s:%s", subject, target, s.Computer))
	if v, ok := AccountMap.Load(id); ok {
		if e, ok := v.(*AccountEnt); ok {
			incAcountEnt(e, s.EventID)
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &AccountEnt{
		Subject:   subject,
		Computer:  s.Computer,
		Count:     0,
		Target:    target,
		LastTime:  ts,
		FirstTime: ts,
	}
	incAcountEnt(e, s.EventID)
	AccountMap.Store(id, e)
}

func incAcountEnt(e *AccountEnt, eventID int) {
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

func sendAccount() {
	AccountMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*AccountEnt); ok {
			if debug {
				log.Printf("account id=%s,e=%v", k, e)
			}
			accountCount++
			syslogCh <- &syslogEnt{
				Severity: 6,
				Time:     time.Now(),
				Msg:      e.String(),
			}
			AccountMap.Delete(k)
		}
		return true
	})
}
