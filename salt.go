package passwordhashing

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/go-zoox/errors"
)

func generateSalt(len int) (string, error) {
	salt := make([]byte, len)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.Wrap(err, "Failed to generate salt")
	}

	return base64.StdEncoding.EncodeToString(salt), nil
}
