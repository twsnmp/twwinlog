package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type syslogEnt struct {
	Time     time.Time
	Severity int
	Msg      string
}

var syslogCh chan *syslogEnt
var syslogCount = 0

func startSyslog(ctx context.Context) {
	syslogCh = make(chan *syslogEnt, 1000)
	dstList := strings.Split(syslogDst, ",")
	dst := []net.Conn{}
	for _, d := range dstList {
		if !strings.Contains(d, ":") {
			d += ":514"
		}
		s, err := net.Dial("udp", d)
		if err != nil {
			log.Fatal(err)
		}
		syslogCh <- &syslogEnt{
			Severity: 6,
			Msg:      fmt.Sprintf("start send syslog to %s", d),
		}
		dst = append(dst, s)
	}
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	defer func() {
		for _, d := range dst {
			d.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			log.Println("stop syslog")
			return
		case l := <-syslogCh:
			syslogCount++
			s := fmt.Sprintf("<%d>%s %s twwinlog: %s", 21*8+l.Severity, l.Time.Format("2006-01-02T15:04:05-07:00"), host, l.Msg)
			for _, d := range dst {
				d.Write([]byte(s))
			}
		}
	}
}
