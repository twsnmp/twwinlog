package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var mqttCh = make(chan interface{}, 2000)

type mqttAccountDataEnt struct {
	Time      string `json:"time"`
	Target    string `json:"target"`
	Subject   string `json:"subject"`
	Computer  string `json:"computer"`
	Count     int    `json:"count"`
	Edit      int    `json:"edit"`
	Other     int    `json:"other"`
	Password  int    `json:"password"`
	FirstTime string `json:"first_time"`
	LastTime  string `json:"last_time"`
}

type mqttEventIDDataEnt struct {
	Time      string `json:"time"`
	Computer  string `json:"computer"`
	Provider  string `json:"provider"`
	Channel   string `json:"channel"`
	EventID   int    `json:"event_id"`
	Level     string `json:"level"`
	Total     int    `json:"total"`
	Count     int    `json:"count"`
	FirstTime string `json:"first_time"`
	LastTime  string `json:"last_time"`
}

type mqttKerberosDataEnt struct {
	Time       string `json:"time"`
	TicketType string `json:"ticket_type"`
	Target     string `json:"target"`
	Computer   string `json:"computer"`
	IP         string `json:"ip"`
	Service    string `json:"service"`
	Count      int    `json:"count"`
	Failed     int    `json:"failed"`
	LastStatus string `json:"last_status"`
	LastCert   string `json:"last_cert"`
	FirstTime  string `json:"first_time"`
	LastTime   string `json:"last_time"`
}

type mqttPrivilegeDataEnt struct {
	Time      string `json:"time"`
	Subject   string `json:"subject"`
	Computer  string `json:"computer"`
	Count     int    `json:"count"`
	FirstTime string `json:"first_time"`
	LastTime  string `json:"last_time"`
}

type mqttProcessDataEnt struct {
	Time        string `json:"time"`
	Computer    string `json:"computer"`
	Process     string `json:"process"`
	Count       int    `json:"count"`
	StartCount  int    `json:"start_count"`
	ExitCount   int    `json:"exit_count"`
	LastSubject string `json:"last_subject"`
	LastStatus  string `json:"last_status"`
	LastParent  string `json:"last_parent"`
	FirstTime   string `json:"first_time"`
	LastTime    string `json:"last_time"`
	SendTime    int64  `json:"send_time"`
}

type mqttTaskDataEnt struct {
	Time      string `json:"time"`
	Subject   string `json:"subject"`
	Computer  string `json:"computer"`
	TaskName  string `json:"task_name"`
	Count     int    `json:"count"`
	FirstTime string `json:"first_time"`
	LastTime  string `json:"last_time"`
	SendTime  int64  `json:"send_time"`
}

type mqttStatsDataEnt struct {
	Time   string  `json:"time"`
	Total  int     `json:"total"`
	Count  int     `json:"count"`
	PS     float64 `json:"ps"`
	Params string  `json:"params"`
}

type mqttMessageDataEnt struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

type mqttMonitorDataEnt struct {
	Time    string  `json:"time"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Load    float64 `json:"load"`
	Sent    uint64  `json:"sent"`
	Recv    uint64  `json:"recv"`
	TxSpeed float64 `json:"tx_speed"`
	RxSpeed float64 `json:"rx_speed"`
	Process int     `json:"process"`
}

func startMQTT(ctx context.Context) {
	if mqttDst == "" {
		return
	}
	broker := mqttDst
	if !strings.Contains(broker, "://") {
		broker = "tcp://" + broker
	}
	if strings.LastIndex(broker, ":") <= 5 {
		broker += ":1883"
	}
	log.Printf("start mqtt broker=%s", broker)
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	if mqttUser != "" && mqttPassword != "" {
		opts.SetUsername(mqttUser)
		opts.SetPassword(mqttPassword)
	}
	opts.SetClientID(mqttClientID)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second * 10)
	opts.SetMaxReconnectInterval(time.Minute)
	opts.SetWriteTimeout(time.Second * 10)
	opts.SetOnConnectHandler(func(c mqtt.Client) {
		log.Println("mqtt connected")
	})
	opts.SetConnectionLostHandler(func(c mqtt.Client, err error) {
		log.Printf("mqtt connection lost: %v", err)
	})

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Printf("mqtt initial connect error: %v (will retry in background)", token.Error())
	}

	defer client.Disconnect(250)
	for {
		select {
		case <-ctx.Done():
			log.Println("stop mqtt")
			return
		case msg := <-mqttCh:
			if s := makeMqttData(msg); s != "" {
				if debug {
					log.Println(s)
				}
				if client.IsConnected() {
					token := client.Publish(getMqttTopic(msg), 1, false, s)
					go func(t mqtt.Token) {
						if t.Wait() && t.Error() != nil {
							// Only log error if not connected or it's not a common transient error
							if client.IsConnected() {
								log.Printf("mqtt publish error: %v", t.Error())
							}
						}
					}(token)
				}
			}
		}
	}
}

func getMqttTopic(msg interface{}) string {
	r := mqttTopic
	switch msg.(type) {
	case *mqttEventIDDataEnt:
		r += "/EventID"
	case *mqttAccountDataEnt:
		r += "/Account"
	case *mqttKerberosDataEnt:
		r += "/Kerberos"
	case *mqttPrivilegeDataEnt:
		r += "/Privilege"
	case *mqttProcessDataEnt:
		r += "/Process"
	case *mqttTaskDataEnt:
		r += "/Task"
	case *mqttStatsDataEnt:
		r += "/Stats"
	case *mqttMessageDataEnt:
		r += "/Message"
	case *mqttMonitorDataEnt:
		r += "/Monitor"
	default:
		log.Printf("getMqttTopic: unknown msg type %T", msg)
	}
	return r
}

func makeMqttData(msg interface{}) string {
	if j, err := json.Marshal(msg); err == nil {
		return string(j)
	}
	return ""
}

func publishMQTT(msg interface{}) {
	if mqttDst == "" {
		return
	}
	select {
	case mqttCh <- msg:
	default:
		if debug {
			log.Println("mqtt channel full, skipping message")
		}
	}
}
