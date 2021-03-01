package events

import (
	"fmt"
	"reflect"
	"testing"
)

func TestDetectHeader(t *testing.T) {
	compareHeader(&Header{Length: 353, EventType: EventTypeText, Estimated: false}, []byte{3, 0, 0, 0, 97, 1, 0, 0}, t)
	compareHeader(&Header{Length: 320, EventType: EventTypeText, Estimated: false}, []byte{3, 0, 0, 0, 64, 1, 0, 0}, t)
	compareHeader(&Header{Length: 76, EventType: EventTypeText, Estimated: false}, []byte{3, 0, 0, 0, 76, 0, 0, 0}, t)
	compareHeader(&Header{Length: 48, EventType: EventTypeWeather, Estimated: false}, []byte{3, 7, 0, 0, 48, 0, 0, 0}, t)
	compareHeader(&Header{Length: 2712, EventType: EventTypeEvent, Estimated: false}, []byte{3, 2, 0, 0, 152, 10, 0, 0}, t)
	compareHeader(&Header{Length: 1496, EventType: EventTypeEventtext, Estimated: false}, []byte{3, 3, 0, 0, 216, 5, 0, 0}, t)
	compareHeader(&Header{Length: 82888, EventType: EventTypeFile, Estimated: false}, []byte{3, 1, 0, 0, 200, 67, 1, 0}, t)
	compareHeader(&Header{Length: 87636, EventType: EventTypeFile, Estimated: true}, []byte{3, 1, 128, 0, 84, 86, 1, 0}, t)
}

func compareHeader(expected *Header, bytes []byte, t *testing.T) {
	result, _ := IdentifyHeader(bytes)
	if !reflect.DeepEqual(expected, result) {
		fmt.Printf("expected: %+v\n", expected)
		fmt.Printf("result: %+v\n", result)
		t.Error("Header are not equals")
	}
}

func TestInitBinaryEvent(t *testing.T) {
	data := []byte{82, 182, 253, 14, 16, 2, 194, 21, 255, 255, 33, 90, 21, 161, 245, 123, 107, 188, 116, 147, 24, 4, 182, 63}
	eventType := EventTypeEvent

	compareEvent(&BinaryEvent{
		EventType: eventType,
		Events: []Event{{
			UUID:  "0efdb652-0210-15c2-ffff215a15a1f57b",
			Value: 0.08600000000000001,
		},
		}}, data, EventTypeEvent, t)
}

func TestTextEvent(t *testing.T) {
	data := []byte{154, 93, 143, 21, 176, 0, 254, 84, 255, 255, 134, 38, 194, 102, 59, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 104, 115, 118, 40, 52, 50, 44, 55, 54, 44, 55, 55, 41, 41, 41, 0, 41, 91, 143, 21, 144, 0, 60, 47, 255, 255, 60, 228, 63, 169, 174, 197, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 154, 93, 143, 21, 175, 0, 165, 84, 255, 255, 134, 38, 194, 102, 59, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 91, 93, 93, 56}
	eventType := EventTypeEventtext

	compareEvent(&BinaryEvent{
		EventType: eventType,
		Events: []Event{
			{
				UUID:     "158f5d9a-00b0-54fe-ffff8626c2663bec",
				UUIDIcon: "00000000-0000-0000-0000000000000000",
				Text:     "hsv(42,76,77)",
			},
			{
				UUID:     "158f5b29-0090-2f3c-ffff3ce43fa9aec5",
				UUIDIcon: "00000000-0000-0000-0000000000000000",
				Text:     "",
			},
			{
				UUID:     "158f5d9a-00af-54a5-ffff8626c2663bec",
				UUIDIcon: "00000000-0000-0000-0000000000000000",
				Text:     "[]",
			},
		}}, data, EventTypeEventtext, t)
}

func compareEvent(expected *BinaryEvent, bytes []byte, eventType EventType, t *testing.T) {
	result := InitBinaryEvent(bytes, eventType)
	if !reflect.DeepEqual(expected, result) {
		fmt.Printf("expected: %+v\n", expected)
		fmt.Printf("result: %+v\n", result)
		t.Error("events are not equals")
	}
}
