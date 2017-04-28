package jwt

import "testing"

var claims = map[string]interface{} {"user": "ru-rocker"}

func TestSerialized(t *testing.T) {
	c := Serialized(claims)
	println(c)
}