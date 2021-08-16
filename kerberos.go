package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type kerberosEnt struct {
	TicketType string
	Target     string
	Computer   string
	IP         string
	Service    string
	Count      int
	Failed     int
	LastStatus string
	LastCert   string
	FirstTime  int64
	LastTime   int64
}

/*
TGT
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
 ST
<EventData>
<Data Name="TargetUserName">dadmin@CONTOSO.LOCAL</Data>
<Data Name="TargetDomainName">CONTOSO.LOCAL</Data>
<Data Name="ServiceName">WIN2008R2$</Data>
<Data Name="ServiceSid">S-1-5-21-3457937927-2839227994-823803824-2102</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="IpAddress">::ffff:10.0.0.12</Data>
<Data Name="IpPort">49272</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{F85C455E-C66E-205C-6B39-F6C60A7FE453}</Data>
<Data Name="TransmittedServices">-</Data>
</EventData>
*/

func (e *kerberosEnt) String() string {
	return fmt.Sprintf("type=Kerberos,target=%s,computer=%s,ip=%s,service=%s,ticketType=%s,count=%d,failed=%d,status=%s,cert=%s,ft=%s,lt=%s",
		e.Target, e.Computer, e.IP, e.Service, e.TicketType, e.Count, e.Failed,
		e.LastStatus, e.LastCert,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var kerberosMap sync.Map

func updateKerberos(s *System, l string, t time.Time) {
	targetUserName := getEventData(reTargetUserName, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	serviceName := getEventData(reServiceName, l)
	ipAddress := getEventData(reIpAddress, l)
	cert := getEventData(reCertIssuerName, l) + ":" + getEventData(reCertSerialNumber, l)
	status := getKerberosFailCode(getEventData(reStatus, l))
	ticketType := "TGT"
	if s.EventID == 4769 {
		ticketType = "ST"
	}
	ts := t.Unix()
	target := fmt.Sprintf("%s@%s", targetUserName, targetDomainName)
	id := fmt.Sprintf("%s:%s:%s:%s:%s", target, s.Computer, ipAddress, serviceName, ticketType)
	if status != "" {
		syslogCh <- &syslogEnt{
			Severity: 4,
			Time:     t,
			Msg: fmt.Sprintf("type=KerberosFailed,target=%s,computer=%s,ip=%s,service=%s,ticketType=%s,status=%s,time=%s",
				target, s.Computer, ipAddress, serviceName, ticketType, status,
				t.Format(time.RFC3339),
			),
		}
	}
	if v, ok := kerberosMap.Load(id); ok {
		if e, ok := v.(*kerberosEnt); ok {
			e.Count++
			if status != "" {
				e.Failed++
			}
			e.LastStatus = status
			e.LastCert = cert
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &kerberosEnt{
		Count:      1,
		Target:     target,
		Computer:   s.Computer,
		IP:         ipAddress,
		Service:    serviceName,
		TicketType: ticketType,
		LastCert:   cert,
		LastStatus: status,
		LastTime:   ts,
		FirstTime:  ts,
	}
	if status != "" {
		e.Failed = 1
	}
	kerberosMap.Store(id, e)
}

func sendKerberos() {
	kerberosMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*kerberosEnt); ok {
			if debug {
				log.Printf("kerberosTGT id=%s,e=%v", k, e)
			}
			kerberosCount++
			syslogCh <- &syslogEnt{
				Severity: 6,
				Time:     time.Now(),
				Msg:      e.String(),
			}
			kerberosMap.Delete(k)
		}
		return true
	})
}

func getKerberosFailCode(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	switch c {
	case "":
		return ""
	case "0x0":
		return ""
	case "0x6":
		return "BadUserName"
	case "0x7":
		return "NewComputer"
	case "0x9":
		return "ResetPassword"
	case "0xc":
		return "Workstation"
	case "0x12":
		return "Account"
	case "0x17":
		return "ExpiredPassword"
	case "0x18":
		return "BadPassword"
	case "0x25":
		return "ClockSync"
	}
	return "Unknown_" + c
}
