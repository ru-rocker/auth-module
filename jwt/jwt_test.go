package jwt

import (
	"testing"
	"github.com/ru-rocker/auth-module"
	"time"
	"github.com/kr/pretty"
)

var auth = Auth{
	Claims: map[string]interface{}{"user": "ru-rocker"},
	Subject: "lalalala",
	Expiration: time.Now().Add(5 * time.Minute),
	NotBefore: time.Now(),
	IssueAt: time.Now(),
	JwtId: "JWTID",
	Issuer: "ru-rocker.com",
	Kid: "kid",
}

func TestSerialized(t *testing.T) {
	c, _ := Serialized(auth, []byte("ru-rockker"), authmodule.SigningMethodHS384)
	println(string(c))
	j, _ := Parse(c, time.Second, time.Second)
	pretty.Print(j)
}
