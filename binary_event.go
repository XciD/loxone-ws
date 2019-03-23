package loxonews

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
)

// Event represent a Loxone event with an UUID and a Value
type Event struct {
	UUID  string
	Value float64
}

type binaryEvent struct {
	eventType eventType
	events    []*Event
	data      *[]byte
}

type header struct {
	eventType eventType
	length    int
	estimated bool
	empty     bool
}

var emptyHeader = &header{empty: true}

type eventType int32

const (
	text         eventType = 0
	file         eventType = 1
	event        eventType = 2
	eventtext    eventType = 3
	daytimer     eventType = 4
	outofservice eventType = 5
	keepalive    eventType = 6
	weather      eventType = 7
)

func (e *binaryEvent) readEventText(bytes *[]byte) {

}

func (e *binaryEvent) readEvent(dataRef *[]byte) {
	data := *dataRef
	reader := bytes.NewReader(data)
	// 1 event = 24 Bytes
	p := make([]byte, 24)
	events := make([]*Event, 0)
	for {
		n, err := reader.Read(p)
		if err == io.EOF {
			break
		}
		events = append(events, createEvent(p[:n]))
	}

	e.events = events
}

func createEvent(eventRaw []byte) *Event {
	uuid := readUUID(eventRaw[0:16])
	value := math.Float64frombits(binary.LittleEndian.Uint64(eventRaw[16:24]))
	return &Event{
		UUID:  uuid,
		Value: value,
	}
}

func identifyHeader(bytes []byte) (*header, error) {
	if len(bytes) != 8 {
		return nil, errors.New("error: wrong binary header received")
	}
	eventTypeValue := bytes[1]
	length := int(binary.LittleEndian.Uint32(bytes[4:]))

	estimated := false
	if bytes[2] == 128 {
		estimated = true
	}

	return &header{
		eventType: eventType(eventTypeValue),
		length:    length,
		estimated: estimated,
	}, nil
}

func initBinaryEvent(bytes *[]byte, eventType eventType) *binaryEvent {
	binaryEvent := &binaryEvent{eventType: eventType}

	switch eventType {
	case eventtext:
		binaryEvent.readEventText(bytes)
	case event:
		binaryEvent.readEvent(bytes)
	case daytimer:
		// TODO
	case weather:
		// TODO
	}

	return binaryEvent
}

func readUUID(data []byte) string {
	values := []string{
		extract32Bytes(data[0:4]),
		extract16Bytes(data[4:6]),
		extract16Bytes(data[6:8]),
		extract64Bytes(data[8:16]),
	}

	return strings.Join(values, "-")
}

func extract16Bytes(data []byte) string {
	b := make([]byte, len(data))
	u := binary.LittleEndian.Uint16(data)
	binary.BigEndian.PutUint16(b, u)
	return hex.EncodeToString(b)
}
func extract32Bytes(data []byte) string {
	b := make([]byte, len(data))
	u := binary.LittleEndian.Uint32(data)
	binary.BigEndian.PutUint32(b, u)
	return hex.EncodeToString(b)
}
func extract64Bytes(data []byte) string {
	return hex.EncodeToString(data)
}
