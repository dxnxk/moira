package graylog

import (
	"flag"
	"fmt"
	"github.com/moira-alert/moira"
	"gopkg.in/Graylog2/go-gelf.v2/gelf"
	"io"
	"log"
	"os"
	"strconv"
	"time"
)

// Sender implements moira sender interface
type Sender struct {
	GraylogHost string
	log         moira.Logger
	Template    *template.Template
	location    *time.Location
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
	sender.location = location

	return nil
}

// SendEvents implements Sender interface Send
func (sender *Sender) SendEvents(events moira.NotificationEvents, contact moira.ContactData, trigger moira.TriggerData, throttled bool) error {

	state := events.GetSubjectState()
	tags := trigger.GetTags()

	if sender.GraylogHost != "" {
		g, err := gelf.NewTCPWriter(sender.GraylogHost)
	}

	m := g.WriteMessage(gelf.Message{
		Version:      "1.1__test",
		Host:         "localhost__test",
		ShortMessage: "Sample test__test",
		FullMessage:  "Stacktrace__test",
		Timestamp:    time.Now().Unix(),
		Level:        1,
	})

	if err := g.GelfWriter.Close(); err != nil {
		return err
	}

	return nil
}

func (sender *Sender) setLogger(logger moira.Logger) {
	sender.log = logger
}
