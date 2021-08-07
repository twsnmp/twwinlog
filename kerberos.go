package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type kerberosEnt struct {
	Target       string
	TargetSid    string
	Computer     string
	Count        int
	Failed       int
	ChangeIP     int
	ChangeStatus int
	LastStatus   string
	LastIP       string
	FirstTime    int64
	LastTime     int64
	SendTime     int64
}

/*
<EventData>
 <Data Name="TargetUserName">dadmin</Data>
 <Data Name="TargetDomainName">CONTOSO.LOCAL</Data>
 <Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data>
 <Data Name="ServiceName">krbtgt</Data>
 <Data Name="ServiceSid">S-1-5-21-3457937927-2839227994-823803824-502</Data>
 <Data Name="TicketOptions">0x40810010</Data>
 <Data Name="Status">0x0</Data>
 <Data Name="TicketEncryptionType">0x12</Data>
 <Data Name="PreAuthType">15</Data>
 <Data Name="IpAddress">::ffff:10.0.0.12</Data>
 <Data Name="IpPort">49273</Data>
 <Data Name="CertIssuerName">contoso-DC01-CA-1</Data>
 <Data Name="CertSerialNumber">1D0000000D292FBE3C6CDDAFA200020000000D</Data>
 <Data Name="CertThumbprint">564DFAEE99C71D62ABC553E695BD8DBC46669413</Data>
 </EventData>
*/

func (e *kerberosEnt) String() string {
	return fmt.Sprintf("type=Logon,target=%s,targetsid=%s,computer=%s,count=%d,failed=%d,changeStatus=%d,changeIP=%d,status=%s,ip=%s,ft=%s,lt=%s",
		e.Target, e.TargetSid, e.Computer, e.Count, e.Failed,
		e.ChangeStatus, e.ChangeIP,
		e.LastStatus, e.LastIP,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var kerberosMap sync.Map

func updateKerberos(s *System, l string, t time.Time) {
	targetUserName := getEventData(reTargetUserName, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	targetSid := getEventData(reTargetSid, l)
	ipAddress := getEventData(reIpAddress, l)
	status := getFailCode(getEventData(reStatus, l))
	ts := t.Unix()
	id := fmt.Sprintf("%s@%s", targetSid, s.Computer)
	target := fmt.Sprintf("%s@%s", targetUserName, targetDomainName)
	if v, ok := kerberosMap.Load(id); ok {
		if e, ok := v.(*kerberosEnt); ok {
			e.Count++
			if ipAddress != "" && ipAddress != e.LastIP {
				e.ChangeIP++
				e.LastIP = ipAddress
			}
			if status != e.LastStatus {
				e.ChangeStatus++
				e.LastStatus = status
			}
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &kerberosEnt{
		Count:      1,
		Target:     target,
		TargetSid:  targetSid,
		LastIP:     ipAddress,
		LastStatus: status,
		LastTime:   ts,
		FirstTime:  ts,
	}
	log.Printf("kerberos=%v", e)
	kerberosMap.Store(id, e)
}

func sendKerberos(rt int64) {
	kerberosMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*kerberosEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete kerberos=%s", k)
				kerberosMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				if debug {
					log.Printf("kerberos id=%s,e=%v", k, e)
				}
				kerberosCount++
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
