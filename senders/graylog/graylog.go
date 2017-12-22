package graylog

import (
	"fmt"
	"github.com/moira-alert/moira"
	"gopkg.in/Graylog2/go-gelf.v2/gelf"
	"strconv"
	"time"
	"github.com/ShowMax/go-fqdn"
)

// Sender implements moira sender interface
type Sender struct {
	GraylogHost string
        FrontURI string
	log         moira.Logger
	//	Template    *template.Template
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

        templateData := struct {
                Link        string
                Description string
                Throttled   bool
                Items       []*templateRow
        }{
                Link:        fmt.Sprintf("%s/trigger/%s", sender.FrontURI, events[0].TriggerID),
                Description: trigger.Desc,
                Throttled:   throttled,
                Items:       make([]*templateRow, 0, len(events)),
        }

        for _, event := range events {

                templateData.Items = append(templateData.Items, &templateRow{
                        Metric:     event.Metric,
                        Timestamp:  time.Unix(event.Timestamp, 0).In(sender.location).Format("15:04 02.01.2006"),
                        Oldstate:   event.OldState,
                        State:      event.State,
                        Value:      strconv.FormatFloat(moira.UseFloat64(event.Value), 'f', -1, 64),
                        WarnValue:  strconv.FormatFloat(trigger.WarnValue, 'f', -1, 64),
                        ErrorValue: strconv.FormatFloat(trigger.ErrorValue, 'f', -1, 64),
                        Message:    moira.UseString(event.Message),
                })

	        glf, err := gelf.NewUDPWriter(sender.GraylogHost)
	        if err != nil {
	                return err
	        }

	        s := fmt.Sprintf("%s %s %s %s", trigger.Name, event.State, event.Metric, strconv.FormatFloat(moira.UseFloat64(event.Value), 'f', -1, 64))

		f := fmt.Sprintf("Timestamp: %s\nMetric: %s\nOldState: %s\nState: %s\nValue: %s\nWarnValue: %s\nErrorValue: %s\nM_link: %s\nG_link: %s", 
												time.Unix(event.Timestamp, 0).In(sender.location).Format("2006-01-02 15:04:05.999"),
												event.Metric,
												event.OldState,
												event.State,
												strconv.FormatFloat(moira.UseFloat64(event.Value), 'f', -1, 64),
												strconv.FormatFloat(trigger.WarnValue, 'f', -1, 64),
												strconv.FormatFloat(trigger.ErrorValue, 'f', -1, 64),
												fmt.Sprintf("%s/trigger/%s", sender.FrontURI, events[0].TriggerID),
                                                                                                fmt.Sprintf("Link to Grafana"),
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
