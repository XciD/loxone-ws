package loxonews

import (
	"fmt"
	"reflect"
	"testing"
)

func TestDetectHeader(t *testing.T) {
	compareHeader(&header{length: 353, eventType: text, estimated: false}, []byte{3, 0, 0, 0, 97, 1, 0, 0}, t)
	compareHeader(&header{length: 320, eventType: text, estimated: false}, []byte{3, 0, 0, 0, 64, 1, 0, 0}, t)
	compareHeader(&header{length: 76, eventType: text, estimated: false}, []byte{3, 0, 0, 0, 76, 0, 0, 0}, t)
	compareHeader(&header{length: 48, eventType: weather, estimated: false}, []byte{3, 7, 0, 0, 48, 0, 0, 0}, t)
	compareHeader(&header{length: 2712, eventType: event, estimated: false}, []byte{3, 2, 0, 0, 152, 10, 0, 0}, t)
	compareHeader(&header{length: 1496, eventType: eventtext, estimated: false}, []byte{3, 3, 0, 0, 216, 5, 0, 0}, t)
	compareHeader(&header{length: 82888, eventType: file, estimated: false}, []byte{3, 1, 0, 0, 200, 67, 1, 0}, t)
	compareHeader(&header{length: 87636, eventType: file, estimated: true}, []byte{3, 1, 128, 0, 84, 86, 1, 0}, t)
}

func compareHeader(expected *header, bytes []byte, t *testing.T) {
	result, _ := identifyHeader(bytes)
	if !reflect.DeepEqual(expected, result) {
		fmt.Printf("expected: %+v\n", expected)
		fmt.Printf("result: %+v\n", result)
		t.Error("header are not equals")
	}
}

func TestInitBinaryEvent(t *testing.T) {
	data := []byte{82, 182, 253, 14, 16, 2, 194, 21, 255, 255, 33, 90, 21, 161, 245, 123, 107, 188, 116, 147, 24, 4, 182, 63}
	eventType := event

	compareEvent(&binaryEvent{
		eventType: eventType,
		events: []*Event{{
			UUID:  "0efdb652-0210-15c2-ffff215a15a1f57b",
			Value: 0.08600000000000001,
		},
		}}, data, event, t)
}

func compareEvent(expected *binaryEvent, bytes []byte, eventType eventType, t *testing.T) {
	result := initBinaryEvent(&bytes, eventType)
	if !reflect.DeepEqual(expected, result) {
		fmt.Printf("expected: %+v\n", expected)
		fmt.Printf("result: %+v\n", result)
		t.Error("events are not equals")
	}
}
