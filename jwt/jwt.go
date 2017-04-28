package jwt

import (
	"github.com/SermoDigital/jose/jwt"
	"time"
	"github.com/SermoDigital/jose/jws"
	"github.com/ru-rocker/auth-module"
)

type Auth struct{
	Issuer string
	IssueAt time.Time
	Expiration time.Time
	NotBefore time.Time
	Subject string
	JwtId string
	Kid interface{}
	Claims map[string] interface{}
}

//function to generate JWT encoded string
//see https://tools.ietf.org/html/rfc7519
func Serialized(auth Auth, key []byte, method auth_module.SigningMethod) string {
	c := jwt.Claims(auth.Claims)

	if iss := auth.Issuer; iss != "" {
		c.SetIssuer(iss)
	}

	if iat := auth.IssueAt; iat != nil {
		c.SetIssuedAt(iat)
	}

	if nbf := auth.NotBefore; nbf != nil {
		c.SetNotBefore(nbf)
	}

	if exp := auth.Expiration; exp != nil {
		c.SetExpiration(exp)
	}

	if sub := auth.Subject; sub != "" {
		c.SetSubject(sub)
	}

	if jwtid := auth.JwtId; jwtid != "" {
		c.SetJWTID(jwtid)
	}

	j := jws.NewJWT(c, method)
	if kid := auth.Kid; kid != "" {
		h := j.(jws.JWS).Protected()
		h.Set("kid", kid)
	}

	return j.
}