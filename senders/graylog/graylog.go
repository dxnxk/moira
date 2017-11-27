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

	glf, err := gelf.NewUDPWriter(sender.GraylogHost)
	if err != nil {
		return err
	}

	msg := gelf.Message{
		Version: "1.1",
		Host:    "mineproxy",
		Short:   "A_short_message",
		Full:    tags,
		Level:   5,
	}
	if err := glf.WriteMessage(&msg); err != nil {
		return err
	}

	return nil
}

func (sender *Sender) setLogger(logger moira.Logger) {
	sender.log = logger
}
