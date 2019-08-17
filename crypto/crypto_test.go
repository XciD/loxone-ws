package crypto

import (
	"testing"
)

func TestEncryptAES(t *testing.T) {
	s, _ := EncryptAES("salt/d93b/jdev/sys/getkey2/xcid", "c8afa9a257c1577892d940afa82435550bbcc52bc2ff9d49d1c6aea5a71bf4a8", "a74b457d12e5c00520292ca83b03aac3")

	if s != "FqlXx4NrS7XYxddF8kTP1dadaH9FY/MBt9Z1zC/ANqI=" {
		println(s)
		println("FqlXx4NrS7XYxddF8kTP1dadaH9FY/MBt9Z1zC/ANqI=")
		t.Error("AES encrypt not working")
	}
}

func TestDecryptAES(t *testing.T) {
	s, err := DecryptAES("rJ3XZcwKdfi6A1bK4rvS+KnoeBqBgwEKLUJgNq2UOtG46SCyG1w3Iq/2zs/Bp56oYJ7EYi7YSqLRpLlcBCjvEdnrz6CfC9OCH29nsY44Zb9gxEO7eepgdPxUGtq5Awkb2L6/GyWmll6xmGOAdOStkiG1c65T/jnPeMQ6eB3T/0Z+yFwb1TvkgRXJlJThXgkqsDMK6X1mxQfVrxTGEQmJY0NBVLGpFNNT6IF2liXIRR7PGdCfEuEhkobcZBjNJmIIE6SRk2I3kZk0VEj87nSKPBA0eZmziIR6PgBZp6FHoXaXtbmhFdIppk03GzL+bfyb", "307828077baa0961a0333a607efc2225de69b30d07e0d6b7ff872aab4265d7f3", "b1d6400c44a40a09aa11b98bbce5bff7")

	if err != nil {
		t.Fatal(err)
	}

	if string(s) != `{"LL":{"control":"jdev/sys/getkey2/xcid","code":200,"value":{"key":"36443338424239373941333733454244443144383246384638323545424545313734333237314231","salt":"31303532383435312D303137632D303762662D66666666633338393333373436383134"}}}` {
		t.Errorf("AES Decrypt not working: %s", string(s))
	}
}

func TestComputeHmac256(t *testing.T) {
	s := ComputeHmac256("user:29798721D364CF650CC24C3C2B8F6CF5F73C204C", "33323346364341453435414635323433344239343045334230344143334133304443434544304538")

	if s != "e3f9c5020c414d7601ae2b44d329bd97d9bb5b8c" {
		t.Error("TestComputeHmac256 not working")
	}
}
