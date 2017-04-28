package auth_module

import "github.com/SermoDigital/jose/crypto"

type SigningMethod crypto.SigningMethod


var (
	SigningMethodHS256 = SigningMethod(crypto.SigningMethodES256)
	SigningMethodHS384 = SigningMethod(crypto.SigningMethodHS384)
	SigningMethodHS512 = SigningMethod(crypto.SigningMethodHS512)
)