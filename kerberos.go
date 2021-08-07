package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type kerberosTGTEnt struct {
	Target       string
	TargetSid    string
	IP           string
	Computer     string
	Count        int
	Failed       int
	ChangeStatus int
	ChangeCert   int
	LastStatus   string
	LastCert     string
	FirstTime    int64
	LastTime     int64
	SendTime     int64
}

type kerberosSTEnt struct {
	Target       string
	ServiceName  string
	ServiceSid   string
	IP           string
	Computer     string
	Count        int
	Failed       int
	ChangeStatus int
	LastStatus   string
	FirstTime    int64
	LastTime     int64
	SendTime     int64
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

func (e *kerberosTGTEnt) String() string {
	return fmt.Sprintf("type=KerberosTGT,target=%s,sid=%s,ip=%s,computer=%s,count=%d,failed=%d,changeStatus=%d,changeCert=%d,status=%s,cert=%s,ft=%s,lt=%s",
		e.Target, e.TargetSid, e.IP, e.Computer, e.Count, e.Failed,
		e.ChangeStatus, e.ChangeCert,
		e.LastStatus, e.LastCert,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

func (e *kerberosSTEnt) String() string {
	return fmt.Sprintf("type=KerberosST,target=%s,servcie=%s,sid=%s,ip=%s,computer=%s,count=%d,failed=%d,changeStatus=%d,status=%s,ft=%s,lt=%s",
		e.Target, e.ServiceName, e.ServiceSid, e.IP, e.Computer, e.Count, e.Failed,
		e.ChangeStatus, e.LastStatus,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var kerberosTGTMap sync.Map

func updateKerberosTGT(s *System, l string, t time.Time) {
	targetUserName := getEventData(reTargetUserName, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	targetSid := getEventData(reTargetSid, l)
	ipAddress := getEventData(reIpAddress, l)
	cert := getEventData(reCertIssuerName, l) + ":" + getEventData(reCertSerialNumber, l)
	status := getKerberosFailCode(getEventData(reStatus, l))
	ts := t.Unix()
	id := fmt.Sprintf("%s@%s<%s", targetSid, s.Computer, ipAddress)
	target := fmt.Sprintf("%s@%s", targetUserName, targetDomainName)
	if status != "" {
		syslogCh <- &syslogEnt{
			Severity: 4,
			Time:     t,
			Msg: fmt.Sprintf("type=KerberosTGTFailed,target=%s,sid=%s,ip=%s,status=%s,time=%s",
				target, targetSid, ipAddress, status,
				t.Format(time.RFC3339),
			),
		}
	}
	if v, ok := kerberosTGTMap.Load(id); ok {
		if e, ok := v.(*kerberosTGTEnt); ok {
			e.Count++
			if status != "" {
				e.Failed++
			}
			if status != e.LastStatus {
				e.ChangeStatus++
				e.LastStatus = status
			}
			if cert != e.LastCert {
				e.ChangeCert++
				e.LastCert = cert
			}
			if e.LastTime < ts {
				e.LastTime = ts
			}
		}
		return
	}
	e := &kerberosTGTEnt{
		Count:      1,
		Target:     target,
		TargetSid:  targetSid,
		Computer:   s.Computer,
		IP:         ipAddress,
		LastCert:   cert,
		LastStatus: status,
		LastTime:   ts,
		FirstTime:  ts,
	}
	if status != "" {
		e.Failed = 1
	}
	kerberosTGTMap.Store(id, e)
}

func sendKerberosTGT(rt int64) {
	kerberosTGTMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*kerberosTGTEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete TGT=%s", k)
				kerberosTGTMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				if debug {
					log.Printf("kerberosTGT id=%s,e=%v", k, e)
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

var kerberosSTMap sync.Map

func updateKerberosST(s *System, l string, t time.Time) {
	targetUserName := getEventData(reTargetUserName, l)
	targetDomainName := getEventData(reTargetDomainName, l)
	serviceName := getEventData(reServiceName, l)
	serviceSid := getEventData(reServiceSid, l)
	ipAddress := getEventData(reIpAddress, l)
	status := getKerberosFailCode(getEventData(reStatus, l))
	ts := t.Unix()
	target := fmt.Sprintf("%s@%s", targetUserName, targetDomainName)
	id := fmt.Sprintf("%s@%s:%s<%s", serviceSid, s.Computer, target, ipAddress)
	if status != "" {
		syslogCh <- &syslogEnt{
			Severity: 4,
			Time:     t,
			Msg: fmt.Sprintf("type=KerberosSTFailed,target=%s,servcie=%s,sid=%s,ip=%s,status=%s,time=%s",
				target, serviceName, serviceSid, ipAddress, status,
				t.Format(time.RFC3339),
			),
		}
	}
	if v, ok := kerberosSTMap.Load(id); ok {
		if e, ok := v.(*kerberosSTEnt); ok {
			e.Count++
			if status != "" {
				e.Failed++
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
	e := &kerberosSTEnt{
		Count:       1,
		Target:      target,
		Computer:    s.Computer,
		ServiceSid:  serviceSid,
		ServiceName: serviceName,
		IP:          ipAddress,
		LastStatus:  status,
		LastTime:    ts,
		FirstTime:   ts,
	}
	if status != "" {
		e.Failed = 1
	}
	kerberosSTMap.Store(id, e)
}

func sendKerberosST(rt int64) {
	kerberosSTMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(*kerberosSTEnt); ok {
			if e.LastTime < rt {
				log.Printf("delete ST=%s", k)
				kerberosTGTMap.Delete(k)
				return true
			}
			if e.LastTime > e.SendTime {
				if debug {
					log.Printf("kerberosST id=%s,e=%v", k, e)
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

func getKerberosFailCode(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	c = strings.ToLower(c)
	switch c {
	case "0x0":
		return ""
	case "0x6":
		return "Bad User Name"
	case "0x7":
		return "New Computer"
	case "0x9":
		return "Reset Password"
	case "0xc":
		return "Workstation"
	case "0x12":
		return "Account"
	case "0x17":
		return "Expired Password"
	case "0x18":
		return "Bad Password"
	case "0x25":
		return "Clock Sync"
	}
	return "Unknown:" + c
}
