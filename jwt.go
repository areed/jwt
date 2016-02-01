//Generate and verify JWTs using the HS256 signature algorithm.
package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

//{"alg":"HS256","type":"JWT"}
var header = []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
var separator = []byte(".")

var ErrParse = errors.New("wrong number of segments")
var ErrHeader = errors.New("header must be " + string(header))
var ErrSignature = errors.New("signature verification failed")
var ErrPayload = errors.New("could not parse payload into a claims set")
var ErrExpired = errors.New("expired JWT")

type Claims struct {
	Iss string `json:"iss,omitempty"`
	Aud string `json:"aud,omitempty"`
	Exp int64  `json:"exp,omitempty"`
	Iat int64  `json:"iat,omitempty"`
	Sub string `json:"sub,omitempty"`
	Nbf string `json:"nbf,omitempty"`
	Jti string `json:"jti,omitempty"`
}

//Encode constructs a JWT by signing and encoding a claims set.
func Encode(claims *Claims, secret []byte) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	payloadBase64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(payload)))
	base64.RawURLEncoding.Encode(payloadBase64, payload)
	sig := Signature(payloadBase64, secret)
	return bytes.Join([][]byte{header, payloadBase64, sig}, separator), nil
}

func Decode(jwt, secret []byte) (*Claims, error) {
	parts, err := Parse(jwt)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header, parts[0]) {
		return nil, ErrHeader
	}
	if !SignatureOK(parts, secret) {
		return nil, ErrSignature
	}
	claims := &Claims{}
	payload := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	base64.RawURLEncoding.Decode(payload, parts[1])
	err = json.Unmarshal(payload, claims)
	if err != nil {
		return nil, ErrPayload
	}
	return claims, nil
}

//Signature generates the signature of header + separator + payload.
func Signature(payload, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(Message(payload))
	hash := mac.Sum(nil)
	sig := make([]byte, base64.RawURLEncoding.EncodedLen(len(hash)))
	base64.RawURLEncoding.Encode(sig, hash)
	return sig
}

//Stamp mutates a claims argument setting the Iat field to the current time and
//the Exp field to current time plus a term.
func Stamp(claims *Claims, term time.Duration) *Claims {
	now := time.Now()
	claims.Iat = now.Unix()
	claims.Exp = now.Add(term).Unix()
	return claims
}

//Parse splits a JWT into its 3 parts.
func Parse(jwt []byte) ([][]byte, error) {
	var parts = bytes.Split(jwt, separator)
	if len(parts) != 3 {
		return nil, ErrParse
	}
	return parts, nil
}

//Messages returns header + separator + payload - the portion of a JWT that is
//signed.
func Message(payload []byte) []byte {
	return bytes.Join([][]byte{header, payload}, separator)
}

//Check a signature is valid for a message.
func SignatureOK(parts [][]byte, secret []byte) bool {
	return bytes.Equal(Signature(parts[1], secret), parts[2])
}

//CheckExpiration returns true if the JWT is not expired.
func ExpirationOK(claims *Claims) bool {
	return time.Now().Unix() <= claims.Exp
}
