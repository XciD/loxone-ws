package test

import (
	"github.com/XciD/loxone-ws"
	"github.com/XciD/loxone-ws/events"
)

type FakeWebsocket struct {
	hooks    map[string]func(*events.Event)
	commands []string
}

func NewFakeWebsocket() *FakeWebsocket {
	return &FakeWebsocket{
		hooks:    make(map[string]func(*events.Event)),
		commands: make([]string, 0),
	}
}

func (l *FakeWebsocket) AddHook(uuid string, callback func(*events.Event)) {
	l.hooks[uuid] = callback
}
func (l *FakeWebsocket) SendCommand(command string, class interface{}) (*loxone.Body, error) {
	l.commands = append(l.commands, command)
	return &loxone.Body{Code: 200}, nil
}

func (l *FakeWebsocket) Close() {

}

func (l *FakeWebsocket) RegisterEvents() error {
	return nil
}

func (l *FakeWebsocket) GetEvents() chan *events.Event {
	return nil
}

func (l *FakeWebsocket) PumpEvents(stop <-chan bool) {

}

func (l *FakeWebsocket) GetConfig() (*loxone.Config, error) {
	return nil, nil
}

func (l *FakeWebsocket) TriggerEvent(uuid string, value float64) {
	if hook, ok := l.hooks[uuid]; ok {
		hook(&events.Event{Value: value})
	}
}

func (l *FakeWebsocket) GetCommands() []string {
	return l.commands
}
