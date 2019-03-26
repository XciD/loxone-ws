package loxonews

import (
	"testing"
)

func TestEncodeCommand(t *testing.T) {
	encrypt := &encrypt{
		iv:   "a74b457d12e5c00520292ca83b03aac3",
		key:  "c8afa9a257c1577892d940afa82435550bbcc52bc2ff9d49d1c6aea5a71bf4a8",
		salt: "d93b",
	}

	encoded, _ := encrypt.getEncryptedCmd("jdev/sys/getkey2/xcid", requestResponseVal)

	if string(encoded) != "jdev/sys/fenc/FqlXx4NrS7XYxddF8kTP1dadaH9FY%2FMBt9Z1zC%2FANqI%3D" {
		print(string(encoded))
		t.Errorf("Error, cypher methods does'nt match: result %s", encoded)
	}
}

func TestEncryptation_HashUser(t *testing.T) {
	encrypt := &encrypt{
		iv:   "a74b457d12e5c00520292ca83b03aac3",
		key:  "c8afa9a257c1577892d940afa82435550bbcc52bc2ff9d49d1c6aea5a71bf4a8",
		salt: "d93b",
	}

	encoded := encrypt.hashUser("user", "test", "31333338623266642D303135342D363463392D66666666353034663934313032343764", "46324345453737334642443534343439313744394535313539443642424436373144323532423246")

	if encoded != "fe64ac92e98486eed980a8a03401ee175bbd51d3" {
		t.Errorf("Error, hash user password doest not match: result %s", encoded)
	}
}

func TestDeserializeLoxoneResponse(t *testing.T) {
	json := []byte(`{"LL": {"value": "ok", "code": "200", "control": "test"}}`)

	result := &LoxoneSimpleValue{}
	body, _ := deserializeLoxoneResponse(&json, result)

	if result.Value != "ok" {
		t.Errorf("Error during value deserilization")
	}

	if body.Code != 200 {
		t.Errorf("Error during code deserilization")
	}

	if body.Control != "test" {
		t.Errorf("Error during test deserilization")
	}

	json = []byte(`{"LL": {"value": {"key": "ontTimeSalt", "Salt": "Salt"}, "code": 200, "control": "test"}}`)

	resultSalt := &loxoneSalt{}
	body, _ = deserializeLoxoneResponse(&json, resultSalt)

	if resultSalt.Salt != "Salt" {
		t.Errorf("Error during Salt value deserilization")
	}

	if resultSalt.OneTimeSalt != "ontTimeSalt" {
		t.Errorf("Error during Salt value deserilization")
	}

	if body.Code != 200 {
		t.Errorf("Error during code deserilization")
	}
}
