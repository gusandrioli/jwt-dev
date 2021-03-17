package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/russellhaering/gosaml2/uuid"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64 `json:"session_id"`
}

type key struct {
	key     []byte
	created time.Time
}

var currentKID = ""
var keysMockDB = map[string]key{} // replace with db

func main() {}

func GenerateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generatinig new Key: %w", err)
	}

	uid := uuid.NewV4()

	keysMockDB[uid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}
	currentKID = uid.String()

	return nil
}

func CreateToken(claims *UserClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)

	signedToken, err := token.SignedString(keysMockDB[currentKID].key)
	if err != nil {
		return "", fmt.Errorf("token.SignedString: %w", err)
	}

	return signedToken, nil
}

func ParseToken(signedToken string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&UserClaims{},
		func(t *jwt.Token) (interface{}, error) {
			// t is the unverified token to check
			// if same signing algorithm is being used
			if t.Method.Alg() != jwt.SigningMethodES512.Alg() {
				return nil, fmt.Errorf("Invalid signing algorithm")
			}

			// kid is an optional header claim which holds a key identifier
			kid, ok := t.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("Invalid key ID")
			}

			key, ok := keysMockDB[kid]
			if !ok {
				return nil, fmt.Errorf("Invalid key ID")
			}

			return key, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Error in ParseToken while parsing token: %w", err)
	}

	if token.Valid {
		return nil, fmt.Errorf("Error in ParseToken, token is not valid")
	}

	return token.Claims.(*UserClaims), nil
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid SessionID")
	}

	return nil
}

