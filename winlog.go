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
