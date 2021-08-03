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
	if debug {
		lastTime = time.Now().Add(time.Hour * -24)
	}
	sendMonitor()
	timer := time.NewTicker(time.Second * time.Duration(syslogInterval))
	defer timer.Stop()
	total := 0
	count := 0
	for {
		select {
		case <-timer.C:
			count = checkWinlog()
			total += count
			msg := fmt.Sprintf("type=Stats,total=%d,count=%d,ps=%.2f", total, count, float64(count)/float64(syslogInterval))
			if remote != "" {
				msg += ",remote=" + remote
			}
			syslogCh <- &syslogEnt{
				Time:     time.Now(),
				Severity: 6,
				Msg:      msg,
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
	sendEventSummary()
	sendLogonReport(st, rt)
	sendMonitor()
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
	lastTime = st
	return ret
}

var reEvent = regexp.MustCompile(`<Event.+Event>`)
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
	for _, l := range reEvent.FindAllString(string(out), -1) {
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
		switch s.EventID {
		case 4624, 4625, 4648, 4634, 4647:
			updateLogon(s, l, t)
		}
		ret++
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

type EventSummaryEnt struct {
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

func (e *EventSummaryEnt) String() string {
	return fmt.Sprintf("type=Summary,Computer=%s,Channel=%s,Provider=%s,EventID=%d,Total=%d,Count=%d,ft=%s,lt=%s",
		e.Computer, e.Channel, e.Provider, e.EventID, e.Total, e.Count,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339))
}

func updateEventIDMap(s *System, t time.Time) {
	ts := t.Unix()
	id := fmt.Sprintf("%s:%s:%d", s.Computer, s.Provider, s.EventID)
	if v, ok := eventIDMap.Load(id); ok {
		if e, ok := v.(*EventSummaryEnt); ok {
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
	eventIDMap.Store(id, &EventSummaryEnt{
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

func sendEventSummary() {
	eventIDMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*EventSummaryEnt); ok {
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
