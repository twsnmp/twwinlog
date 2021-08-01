package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var busy = false
var lastTime = time.Now()
var logonCount = 0
var logonFailed = 0

var eventIDMap sync.Map

// startWinlog : start monitor windows event log
func startWinlog(ctx context.Context) {
	timer := time.NewTicker(time.Second * time.Duration(syslogInterval))
	defer timer.Stop()
	total := 0
	count := 0
	for {
		select {
		case <-timer.C:
			count = checkWinlog()
			total += count
			syslogCh <- &syslogEnt{
				Time:     time.Now(),
				Severity: 6,
				Msg:      fmt.Sprintf("type=Stats,total=%d,count=%d,ps=%.2f", total, count, float64(count)/float64(syslogInterval)),
			}
			go sendReport()
			log.Printf("total=%d,count=%d,logon=%d,logonFailed=%d", total, count, logonCount, logonFailed)
		case <-ctx.Done():
			log.Println("stop winlog")
			return
		}
	}
}

// syslogでレポートを送信する
func sendReport() {
	if busy {
		log.Printf("send report busy")
		return
	}
	busy = true
	st := time.Now().Add(-time.Second * time.Duration(syslogInterval)).Unix()
	rt := time.Now().Add(-time.Second * time.Duration(retentionData)).Unix()
	sendEventIDMapReport()
	sendLogonReport(st, rt)
	busy = false
}

// Windows Event Log XML format
type System struct {
	EventID       int    `xml:"EventID"`
	Level         int    `xml:"Level"`
	EventRecordID int64  `xml:"EventRecordID"`
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
	Security      struct {
		UserID string `xml:"UserID,attr"`
	}
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	}
}

func checkWinlog() int {
	ret := 0
	st := time.Now()
	for _, c := range []string{"System", "Security", "Application"} {
		ret += checkWinlogCh(c)
	}
	lastTime = st
	return ret
}

var reEvent = regexp.MustCompile(`<Event.+Event>`)
var reSystem = regexp.MustCompile(`<System.+System>`)

func checkWinlogCh(c string) int {
	filter := fmt.Sprintf(`/q:*[System[TimeCreated[@SystemTime>'%s']]]`, lastTime.UTC().Format("2006-01-02T15:04:05"))
	ret := 0
	out, err := exec.Command("wevtutil.exe", "qe", c, filter).Output()
	if err != nil {
		log.Printf("err=%v c=%s filter=%s out=%s", err, c, filter, out)
		return 0
	}
	if len(out) < 5 {
		return 0
	}
	e := new(System)
	for _, l := range reEvent.FindAllString(string(out), -1) {
		l := strings.TrimSpace(l)
		if len(l) < 10 {
			continue
		}
		lsys := reSystem.FindString(l)
		err := xml.Unmarshal([]byte(lsys), e)
		if err != nil {
			log.Printf("xml err=%v %v \n%s", err, e, l)
			continue
		}
		updateEventIDMap(e)
		switch e.EventID {
		case 4624, 4625, 4648, 4634, 4647:
			updateLogon(e, l)
		}
		ret++
	}
	return ret
}

type EventIDEnt struct {
	Computer string
	EventID  int
	Count    int
}

func updateEventIDMap(s *System) {
	id := fmt.Sprintf("%s:%d", s.Computer, s.EventID)
	if v, ok := eventIDMap.Load(id); ok {
		if e, ok := v.(*EventIDEnt); ok {
			e.Count++
		}
		return
	}
	eventIDMap.Store(id, &EventIDEnt{
		EventID:  s.EventID,
		Computer: s.Computer,
		Count:    1,
	})
}

func sendEventIDMapReport() {
	cMap := make(map[string]string)
	eventIDMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*EventIDEnt); ok {
			if _, ok := cMap[e.Computer]; !ok {
				cMap[e.Computer] = fmt.Sprintf("type=IDMap,com=%s,%d=%d", e.Computer, e.EventID, e.Count)
			} else {
				cMap[e.Computer] += fmt.Sprintf(",%d=%d", e.EventID, e.Count)
			}
		}
		eventIDMap.Delete(k)
		return true
	})
	for _, l := range cMap {
		syslogCh <- &syslogEnt{
			Severity: 6,
			Time:     time.Now(),
			Msg:      l,
		}
	}
}

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
	ID            string
	Subject       string
	Target        string
	IPAddress     string
	Computer      string
	Count         int
	Logon         int
	Failed        int
	Logoff        int
	Change        int
	LastLogonType string
	LastSubStatus string
	FirstTime     int64
	LastTime      int64
	SendTime      int64
}

func (e *logonEnt) String() string {
	return fmt.Sprintf("type=Logon,subjct=%s,target=%s,count=%d,change=%d,logon=%d,failed=%d,logoff=%d,llt=%s,lst=%s,ft=%s,lt=%s",
		e.Subject, e.Target, e.Count, e.Change, e.Logon, e.Failed, e.Logoff,
		e.LastLogonType, e.LastSubStatus,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var logonMap sync.Map

func updateLogon(s *System, l string) {
	logonType := getEventData(reLogonType, l)
	subjectUserName := getEventData(reSubjectUserName, l)
	subjectDomainName := getEventData(reSubjectDomainName, l)
	targetUserName := getEventData(reTargetUserName, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	ipAddress := getEventData(reIpAddress, l)
	subStatus := getEventData(reSubStatus, l)
	t := getEventTime(s.TimeCreated.SystemTime)
	ts := t.Unix()
	if s.EventID == 4625 {
		logonFailed++
		syslogCh <- &syslogEnt{
			Severity: 4,
			Time:     t,
			Msg: fmt.Sprintf("type=LogonFailed,subject=%s@%s,target=%s@%s,logonType=%s,ip=%s,status=%s",
				subjectUserName, subjectDomainName, targetUserName, targetDomainName, logonType, ipAddress, subStatus),
		}
	}
	id := fmt.Sprintf("%s@%s:%s@%s:%s:%s", subjectUserName, subjectDomainName, targetUserName, targetDomainName, ipAddress, s.Computer)
	if v, ok := logonMap.Load(id); ok {
		if e, ok := v.(*logonEnt); ok {
			incLogonEnt(e, s.EventID)
			if logonType != e.LastLogonType {
				e.LastLogonType = logonType
				e.Change++
			}
			if subStatus != "" {
				e.LastSubStatus = subStatus
			}
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &logonEnt{
		ID:            id,
		Count:         0,
		Subject:       fmt.Sprintf("%s@%s", subjectUserName, subjectDomainName),
		Target:        fmt.Sprintf("%s@%s", targetUserName, targetDomainName),
		IPAddress:     ipAddress,
		LastLogonType: logonType,
		LastSubStatus: subStatus,
		LastTime:      ts,
		FirstTime:     ts,
	}
	incLogonEnt(e, s.EventID)
	logonMap.Store(id, e)
}

func incLogonEnt(e *logonEnt, eventID int) {
	e.Count++
	switch eventID {
	case 4624:
		e.Logon++
	case 4625:
		e.Failed++
	case 4647:
		e.Logoff++
	}
}

func getEventData(re *regexp.Regexp, l string) string {
	if a := re.FindAllStringSubmatch(l, 1); len(a) > 0 && len(a[0]) > 1 {
		return a[0][1]
	}
	return ""
}

func getEventTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		log.Printf(" err=%v", err)
		return time.Now()
	}
	return t
}

func sendLogonReport(st, rt int64) {
	logonMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*logonEnt); ok {
			if e.LastTime < rt {
				logonMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
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
