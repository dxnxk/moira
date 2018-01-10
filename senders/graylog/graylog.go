package graylog

import (
	"fmt"
	"strings"
	"github.com/moira-alert/moira"
	"gopkg.in/Graylog2/go-gelf.v2/gelf"
	"strconv"
	"time"
	"github.com/ShowMax/go-fqdn"
	"mvdan.cc/xurls"
)

// Sender implements moira sender interface
type Sender struct {
	GraylogHost string
        FrontURI string
	log         moira.Logger
	location *time.Location
}

type templateRow struct {
	Metric     string
	Timestamp  string
	Oldstate   string
	State      string
	Value      string
	WarnValue  string
	ErrorValue string
	Message    string
}

// Init read yaml config
func (sender *Sender) Init(senderSettings map[string]string, logger moira.Logger, location *time.Location) error {
	sender.setLogger(logger)
	sender.GraylogHost = senderSettings["graylog_host"]
	sender.FrontURI = senderSettings["front_uri"]
	sender.location = location
	return nil
}


// Build_desc remakes Desc to include url to grafana, if url exists in Desc.
func Build_desc(url_Desc string, trigger_Desc string, attached_Descr string) string {
	if len(strings.TrimSpace(url_Desc)) == 0 {
		return fmt.Sprintf("\n%s", trigger_Desc)
        } else {
		return fmt.Sprintf("\n%s", attached_Descr)
        }
}

// SendEvents implements Sender interface Send
func (sender *Sender) SendEvents(events moira.NotificationEvents, contact moira.ContactData, trigger moira.TriggerData, throttled bool) error {

        severity := map[string]int32{
            "OK":       5,
            "WARN":     4,
            "CRIT":     2,
            "NODATA":   3,
            "ERROR":    3,
            "TEST":     6,
        }

        desc_url := xurls.Relaxed().FindString(trigger.Desc) // get url from Trigger Description

        for _, event := range events {

		url := strings.Join([]string{desc_url, event.Metric}, "")

		descr := strings.Replace(trigger.Desc, desc_url, url, -1)

	        glf, err := gelf.NewUDPWriter(sender.GraylogHost)
	        if err != nil {
	                return err
	        }

	        s := fmt.Sprintf("%s %s %s %s", trigger.Name, event.State, event.Metric, strconv.FormatFloat(moira.UseFloat64(event.Value), 'f', -1, 64))

		f := fmt.Sprintf("Timestamp: %s\nTrigger: %s\nMetric: %s\nOldState: %s\nState: %s\nValue: %s\nWarnValue: %s\nErrorValue: %s\nLink: %s\nDescription: %s", 
								time.Unix(event.Timestamp, 0).In(sender.location).Format("2006-01-02 15:04:05.999"),
								trigger.Name,
								event.Metric,
								event.OldState,
								event.State,
								strconv.FormatFloat(moira.UseFloat64(event.Value), 'f', -1, 64),
								strconv.FormatFloat(trigger.WarnValue, 'f', -1, 64),
								strconv.FormatFloat(trigger.ErrorValue, 'f', -1, 64),
                                                                fmt.Sprintf("\n%s/trigger/%s", sender.FrontURI, events[0].TriggerID),
								Build_desc(desc_url, trigger.Desc, descr),
								)

	        msg := gelf.Message{
	                Version: "1.1",
	                Host:    fmt.Sprintln(fqdn.Get()),
			Short:   s,
			Full:    f,
	                Level:   severity[event.State],
	        }
	        if err := glf.WriteMessage(&msg); err != nil {
	                return err
	        }
        }
	return nil
}

func (sender *Sender) setLogger(logger moira.Logger) {
	sender.log = logger
}
