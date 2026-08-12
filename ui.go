/*
 * ui.go — serialised line output for the multi-port tunnels.
 *
 * A single writer goroutine owns the output: every public call
 * (Start / Update / Below) is just a message on a channel, so parallel
 * tunnels can never race over stdout. Each message is printed as one
 * plain line, in order. No cursor, no scroll regions, no cleanup.
 */

package main

import (
	"fmt"
	"io"
)

type uiCmd int

const (
	uiCmdInit uiCmd = iota
	uiCmdUpdate
	uiCmdBelow
)

type uiMsg struct {
	cmd  uiCmd
	idx  int
	text string
}

type UI struct {
	ch chan uiMsg
	w  io.Writer
}

func NewUI(w io.Writer) *UI {
	u := &UI{
		ch: make(chan uiMsg, 256),
		w:  w,
	}
	go u.run()
	return u
}

// Start prints the header line.
func (u *UI) Start(header string, n int) {
	u.ch <- uiMsg{cmd: uiCmdInit, text: header}
}

// Update prints the status line for port idx (idx kept for API symmetry).
func (u *UI) Update(idx int, line string) {
	u.ch <- uiMsg{cmd: uiCmdUpdate, idx: idx, text: line}
}

// Below appends a line to the log.
func (u *UI) Below(text string) {
	u.ch <- uiMsg{cmd: uiCmdBelow, text: text}
}

func (u *UI) run() {
	for m := range u.ch {
		switch m.cmd {
		case uiCmdInit, uiCmdUpdate, uiCmdBelow:
			fmt.Fprintln(u.w, m.text)
		}
	}
}
