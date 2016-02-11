package jwt

import (
	"bytes"
	"time"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	claims := &Claims{
		Iss: "whoyou.io",
		Sub: "jane@example.com",
		Iat: 1000,
		Exp: 10000,
		Aud: "whoyou.io",
	}
	secret := []byte("secret")
	jwt, err := Encode(claims, secret)
	if err != nil {
		t.Fatal(err)
	}
	claims, err = Decode(jwt, secret)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncode(t *testing.T) {
	claims := &Claims{
		Iss: "whoyou.io",
		Sub: "john@example.com",
		Exp: 100000,
	}
	jwt, err := Encode(claims, []byte("secret"))
	if err != nil {
		t.Error(err)
	}
	answer := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3aG95b3UuaW8iLCJleHAiOjEwMDAwMCwic3ViIjoiam9obkBleGFtcGxlLmNvbSJ9.xF8mxxOSt5yDGvQfmoO-f2MoDILVQkk-6NKasgAk6_8")
	if !bytes.Equal(jwt, answer) {
		t.Errorf("\n%s\n%s", jwt, answer)
	}
}

func TestDecode(t *testing.T) {
	jwt := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3aG95b3UuaW8iLCJleHAiOjEwMDAwMCwic3ViIjoiam9obkBleGFtcGxlLmNvbSJ9.xF8mxxOSt5yDGvQfmoO-f2MoDILVQkk-6NKasgAk6_8")
	claims, err := Decode(jwt, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "whoyou.io" {
		t.Errorf("Iss: %q", claims.Iss)
	}
}

func TestSignature(t *testing.T) {
	tests := []struct{
		payload, secret, answer []byte
	} {
		{[]byte("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"), []byte("secret"), []byte("TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")},
		{[]byte("eyJpc3MiOiJ3aG95b3UuaW8iLCJzdWIiOiJqb2huQGV4YW1wbGUuY29tICAgIiwiZXhwIjoxMDAwMDB9"), []byte("not so secret after all 50"), []byte("odu9hErBX2pLc0nFz_-0kspfCgbVl0I0SGsd7SqTZy0")},
	}
	for _, r := range tests {
		output := Signature(r.payload, r.secret)
		if !bytes.Equal(output, r.answer) {
			t.Errorf("Signature(%s, %s) => %s, want %s", r.payload, r.secret, output, r.answer)
		}
	}
}

func TestStamp(t *testing.T) {
	claims := &Claims{Exp: 1000, Iat: 900}
	Stamp(claims, time.Minute * 15)
	if claims.Exp == 1000 || claims.Iat == 900 {
		t.Error("Stamp did not update exp or iat field")
	}
	if claims.Iat >= claims.Exp {
		t.Error("Stamp duration not applied correctly")
	}
}

func TestParse(t *testing.T) {
	parts, err := Parse([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3aG95b3UuaW8iLCJzdWIiOiJqb2huQGV4YW1wbGUuY29tICAgIiwiZXhwIjoxMDAwMDB9.odu9hErBX2pLc0nFz_-0kspfCgbVl0I0SGsd7SqTZy0"))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 {
		t.Errorf("%d segments", len(parts))
	}
	if string(parts[0]) != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" {
		t.Errorf("segment 1: %s", parts[0])
	}
	if string(parts[1]) != "eyJpc3MiOiJ3aG95b3UuaW8iLCJzdWIiOiJqb2huQGV4YW1wbGUuY29tICAgIiwiZXhwIjoxMDAwMDB9" {
		t.Errorf("segment 2: %s", parts[1])
	}
	if string(parts[2]) != "odu9hErBX2pLc0nFz_-0kspfCgbVl0I0SGsd7SqTZy0" {
		t.Errorf("segment 3: %s", parts[2])
	}
	parts, err = Parse([]byte("x.y"))
	if err == nil {
		t.Error("parsed 2 segment token")
	}
	parts, err = Parse([]byte("a.b.c.d"))
	if err == nil {
		t.Error("parsed 4 segment token")
	}
}

func TestMessage(t *testing.T) {
	msg := Message([]byte("xyz"))
	if string(msg) != string(header) + ".xyz" {
		t.Errorf("Message(xyz) => %s, want %s", msg, string(header) + ".xyz")
	}
}

func TestSignatureOK(t *testing.T) {
	payload := []byte("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9")
	secret := []byte("secret")
	ok := SignatureOK([][]byte{header, payload, []byte("TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")}, secret)
	if !ok {
		t.Error("SignatureOK rejected a valid signature")
	}
	ok = SignatureOK([][]byte{header, payload, []byte("xTJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")}, secret)
	if ok {
		t.Error("SignatureOK accepted an invalid signature")
	}
}

func TestExpirationOK(t *testing.T) {
	claims := &Claims{Exp: time.Now().Add(time.Second).Unix()}
	ok := ExpirationOK(claims)
	if !ok {
		t.Error("ExpirationOK rejected a live claims set")
	}
	claims.Exp = time.Now().Add(time.Second * -1).Unix()
	ok = ExpirationOK(claims)
	if ok {
		t.Error("ExpirationOK accepted an expired claims set")
	}
}
