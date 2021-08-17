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

	"golang.org/x/sys/windows/registry"
)

var busy = false
var lastTime = time.Now()
var logonCount = 0
var processCount = 0
var kerberosCount = 0
var taskCount = 0
var accountCount = 0
var privilegeCount = 0
var logonFailed = 0

var reLogonType = regexp.MustCompile(`<Data Name='LogonType'>(\d+)</Data>`)
var reSubjectUserName = regexp.MustCompile(`<Data Name='SubjectUserName'>([^<]+)</Data>`)
var reSubjectDomainName = regexp.MustCompile(`<Data Name='SubjectDomainName'>([^<]+)</Data>`)
var reTargetUserName = regexp.MustCompile(`<Data Name='TargetUserName'>([^<]+)</Data>`)
var reTargetDomainName = regexp.MustCompile(`<Data Name='TargetDomainName'>([^<]+)</Data>`)
var reIpAddress = regexp.MustCompile(`<Data Name='IpAddress'>([^<]+)</Data>`)
var reSubStatus = regexp.MustCompile(`<Data Name='SubStatus'>([^<]+)</Data>`)
var reSubjectUserSid = regexp.MustCompile(`<Data Name='SubjectUserSid'>([^<]+)</Data>`)
var reTargetUserSid = regexp.MustCompile(`<Data Name='TargetUserSid'>([^<]+)</Data>`)
var reTargetServerName = regexp.MustCompile(`<Data Name='TargetServerName'>([^<]+)</Data>`)
var reTaskName = regexp.MustCompile(`<Data Name='TaskName'>([^<]+)</Data>`)
var reTargetSid = regexp.MustCompile(`<Data Name='TargetSid'>([^<]+)</Data>`)
var reServiceName = regexp.MustCompile(`<Data Name='ServiceName'>([^<]+)</Data>`)
var reServiceSid = regexp.MustCompile(`<Data Name='ServiceSid'>([^<]+)</Data>`)
var reCertIssuerName = regexp.MustCompile(`<Data Name='CertIssuerName'>([^<]+)</Data>`)
var reCertSerialNumber = regexp.MustCompile(`<Data Name='CertSerialNumber'>([^<]+)</Data>`)

var reSubjectUserNameTag = regexp.MustCompile(`<SubjectUserName>([^<]+)</SubjectUserName>`)
var reSubjectDomainNameTag = regexp.MustCompile(`<SubjectDomainName>([^<]+)</SubjectDomainName>`)
var reSubjectUserSidTag = regexp.MustCompile(`<SubjectUserSid>([^<]+)</SubjectUserSid>`)

const REGISTRY_PATH = "SOFTWARE\\Twise\\TWWINLOG"

// <Data Name='SubjectUserName'>DESKTOP-T6L1D1U$</Data>
// <Data Name='SubjectDomainName'>WORKGROUP</Data>
// <Data Name='TargetUserName'>SYSTEM</Data>
// <Data Name='TargetDomainName'>NT AUTHORITY</Data>
// <Data Name='IpAddress'>-</Data>
// <Data Name='SubStatus'>0xc0000064</Data>
// <Data Name='TargetServerName'>WIN-ABEORAE1LF6.ymitest.local</Data>
// <Data Name="TaskName">\\Microsoft\\StartListener</Data>

var eventIDMap sync.Map

var syslogCount = 0

// startWinlog : start monitor windows event log
func startWinlog(ctx context.Context) {
	param := remote
	if param == "" {
		param = "LOCAL"
	}
	getLastTime()
	if debug {
		lastTime = time.Now().Add(time.Hour * -12)
	}
	sendMonitor(param)
	timer := time.NewTicker(time.Second * time.Duration(syslogInterval))
	defer timer.Stop()
	total := 0
	count := 0
	for {
		select {
		case <-timer.C:
			count = checkWinlog()
			saveLastTime()
			total += count
			msg := fmt.Sprintf("type=Stats,total=%d,count=%d,ps=%.2f,send=%d,param=%s",
				total, count, float64(count)/float64(syslogInterval), syslogCount, param)
			syslogCh <- &syslogEnt{
				Time:     time.Now(),
				Severity: 6,
				Msg:      msg,
			}
			go sendReport(param)
			log.Printf("total=%d,count=%d,syslog=%d,logon=%d,logonFailed=%d,process=%d,task=%d,kerberos=%d,privilege=%d,account=%d",
				total, count, syslogCount, logonCount, logonFailed, processCount, taskCount, kerberosCount,
				privilegeCount, accountCount)
			syslogCount = 0
		case <-ctx.Done():
			log.Println("stop winlog")
			return
		}
	}
}

// getEventData : <EventData>タグ内から情報を取得する
func getEventData(re *regexp.Regexp, l string) string {
	if a := re.FindAllStringSubmatch(l, 1); len(a) > 0 && len(a[0]) > 1 && a[0][1] != "-" {
		return a[0][1]
	}
	return ""
}

// syslogでレポートを送信する
func sendReport(param string) {
	if busy {
		log.Printf("send report busy")
		return
	}
	busy = true
	sendEventID()
	sendLogon()
	sendAccount()
	sendKerberos()
	sendPrivilege()
	sendTask()
	sendProcess()
	sendMonitor(param)
	busy = false
}

// Windows Event Log XML format
type System struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	}
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
	if ret > 0 {
		lastTime = st
	}
	return ret
}

var reSystem = regexp.MustCompile(`<System.+System>`)

func checkWinlogCh(c string) int {
	filter := fmt.Sprintf(`/q:*[System[TimeCreated[@SystemTime>'%s']]]`, lastTime.UTC().Format("2006-01-02T15:04:05"))
	params := []string{"qe", c, filter}
	if remote != "" {
		params = append(params, "/r:"+remote)
		params = append(params, "/u:"+user)
		params = append(params, "/p:"+password)
		if auth != "" {
			params = append(params, "/a:"+auth)
		}
	}
	ret := 0
	out, err := exec.Command("wevtutil.exe", params...).Output()
	if err != nil {
		log.Printf("err=%v c=%s filter=%s", err, c, filter)
		return 0
	}
	if len(out) < 5 {
		return 0
	}
	s := new(System)
	bSec := c == "Security"
	for _, l := range strings.Split(strings.ReplaceAll(string(out), "\n", ""), "</Event>") {
		l := strings.TrimSpace(l)
		if len(l) < 10 {
			continue
		}
		lsys := reSystem.FindString(l)
		err := xml.Unmarshal([]byte(lsys), s)
		if err != nil {
			log.Printf("xml err=%v", err)
			continue
		}
		t := getEventTime(s.TimeCreated.SystemTime)
		updateEventIDMap(s, t)
		ret++
		if !bSec {
			continue
		}
		switch s.EventID {
		case 4624, 4625, 4648, 4634, 4647:
			updateLogon(s, l, t)
		case 4688, 4689:
			updateProcess(s, l, t)
		case 1102:
			sendClearLog(s, l, t)
		case 4698:
			log.Printf("task in %v,%s", s, l)
			updateTask(s, l, t)
		case 4768, 4769:
			updateKerberos(s, l, t)
		case 4672, 4673:
			updatePrivilege(s, l, t)
		case 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781:
			updateAccount(s, l, t)
		}
	}
	return ret
}

func getEventTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		log.Printf(" err=%v", err)
		return time.Now()
	}
	return t
}

type EventIDEnt struct {
	Computer  string
	Provider  string
	Channel   string
	EventID   int
	Level     int
	Total     int
	Count     int
	FirstTime int64
	LastTime  int64
}

func (e *EventIDEnt) String() string {
	return fmt.Sprintf("type=EventID,computer=%s,channel=%s,provider=%s,eventID=%d,total=%d,count=%d,ft=%s,lt=%s",
		e.Computer, e.Channel, e.Provider, e.EventID, e.Total, e.Count,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339))
}

func updateEventIDMap(s *System, t time.Time) {
	ts := t.Unix()
	id := fmt.Sprintf("%s:%s:%d", s.Computer, s.Provider, s.EventID)
	if v, ok := eventIDMap.Load(id); ok {
		if e, ok := v.(*EventIDEnt); ok {
			e.Count++
			e.Total++
			if e.LastTime < ts {
				e.LastTime = ts
			}
			if s.Level != 0 && e.Level != 0 && e.Level > s.Level {
				e.Level = s.Level
			}
		}
		return
	}
	eventIDMap.Store(id, &EventIDEnt{
		EventID:   s.EventID,
		Level:     s.Level,
		Computer:  s.Computer,
		Channel:   s.Channel,
		Provider:  s.Provider.Name,
		Total:     1,
		Count:     1,
		FirstTime: ts,
		LastTime:  ts,
	})
}

func sendEventID() {
	eventIDMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*EventIDEnt); ok {
			if e.Count < 1 {
				return true
			}
			sv := 6
			switch e.Level {
			case 1:
				sv = 2
			case 2:
				sv = 3
			case 3:
				sv = 4
			}
			syslogCh <- &syslogEnt{
				Severity: sv,
				Time:     time.Now(),
				Msg:      e.String(),
			}
			e.Count = 0
		}
		return true
	})
}

func sendClearLog(s *System, l string, t time.Time) {
	subjectUserName := getEventData(reSubjectUserNameTag, l)
	subjectDomainName := getEventData(reSubjectDomainNameTag, l)
	subjectUserSid := getEventData(reSubjectUserSidTag, l)
	syslogCh <- &syslogEnt{
		Severity: 2,
		Time:     t,
		Msg: fmt.Sprintf("type=ClearLog,subject=%s@%s,sid=%s",
			subjectUserName, subjectDomainName, subjectUserSid),
	}
}

// getLastTime from registry
func getLastTime() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, REGISTRY_PATH, registry.QUERY_VALUE)
	if err != nil {
		log.Printf("getLastTime err=%v", err)
		return
	}
	defer k.Close()
	regKey := "LOCAL"
	if remote != "" {
		regKey = remote
	}
	i, _, err := k.GetIntegerValue(regKey)
	if err != nil {
		log.Printf("getLastTime err=%v", err)
		return
	}
	lastTime = time.Unix(int64(i), 0)
	log.Printf("lastTime=%v", lastTime)
}

func saveLastTime() {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, REGISTRY_PATH, registry.ALL_ACCESS)
	if err != nil {
		log.Printf("saveLastTime err=%v", err)
	}
	defer k.Close()
	regKey := "LOCAL"
	if remote != "" {
		regKey = remote
	}
	if err = k.SetQWordValue(regKey, uint64(lastTime.Unix())); err != nil {
		log.Printf("saveLastTime err=%v", err)
	}
}
