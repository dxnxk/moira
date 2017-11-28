package main

import (
	"fmt"
	"gopkg.in/Graylog2/go-gelf.v2/gelf"
)

func main() {

	var GraylogHost string = "10.101.254.21:12215"

	glf, err := gelf.NewUDPWriter(GraylogHost)
	if err != nil {
		fmt.Println(err)
	}

	msg := gelf.Message{
		Version: "1.1",
		Host:    "mineproxy",
		Short:   "A_short_message",
		Full:    "Backtrace_here\n\nmore_stuff",
		Level:   5,
	}

	if err := glf.WriteMessage(&msg); err != nil {
		fmt.Println(err)
	}
}
