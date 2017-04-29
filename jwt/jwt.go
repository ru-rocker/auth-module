package jwt

import (
	"time"
	"github.com/SermoDigital/jose/jws"
	"github.com/ru-rocker/auth-module"
)

type Auth struct {
	Issuer     string
	IssueAt    time.Time
	Expiration time.Time
	NotBefore  time.Time
	Subject    string
	JwtId      string
	Kid        interface{}
	Claims     map[string]interface{}
}

//function to generate JWT encoded string
//see https://tools.ietf.org/html/rfc7519
func Serialized(auth Auth, key []byte, method authmodule.SigningMethod) ([]byte, error) {
	c := jws.Claims(auth.Claims)

	if iss := auth.Issuer; iss != "" {
		c.SetIssuer(iss)
	}

	if iat := auth.IssueAt; iat.IsZero() {
		c.SetIssuedAt(iat)
	}

	if nbf := auth.NotBefore; nbf.IsZero() {
		c.SetNotBefore(nbf)
	}

	if exp := auth.Expiration; exp.IsZero() {
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

	s, err := j.Serialize(key)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// parse auth token with leeway for validating expired and/or not before duration
func Parse(authToken []byte, key []byte, method authmodule.SigningMethod,
	expLeeway time.Duration, nbfLeeway time.Duration) (Auth, error) {
	auth := Auth{}
	jwt, err := jws.ParseJWT([]byte(authToken))
	if err != nil {
		return auth, err
	}

	err = jwt.Validate(key, method)
	if err != nil {
		return auth, err
	}

	c := jwt.Claims()
	err = c.Validate(time.Now(), expLeeway, nbfLeeway)
	if err != nil {
		return auth, err
	}

	if iss, ok := c.Issuer(); ok {
		auth.Issuer = iss
		c.RemoveIssuer()
	}
	if iat, ok := c.IssuedAt(); ok {
		auth.IssueAt = iat
		c.RemoveIssuedAt()
	}
	if nbf, ok := c.NotBefore(); ok {
		auth.NotBefore = nbf
		c.RemoveNotBefore()
	}
	if exp, ok := c.Expiration(); ok {
		auth.Expiration = exp
		c.RemoveExpiration()
	}
	if sub, ok := c.Subject(); ok {
		auth.Subject = sub
		c.RemoveSubject()
	}
	if jwtid, ok := c.JWTID(); ok {
		auth.JwtId = jwtid
		c.RemoveJWTID()
	}

	h := jwt.(jws.JWS).Protected()
	auth.Kid = h.Get("kid")
	auth.Claims = c

	return auth, nil
}
