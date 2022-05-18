package passwordhashing

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-zoox/errors"
	"golang.org/x/crypto/argon2"
)

// Generate generates a password hash.
func Generate(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("Password length cannot be 0")
	}

	salt, _ := generateSalt(saltLen)
	unencodedPassword := argon2.IDKey([]byte(password), []byte(salt), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	encodedPassword := base64.StdEncoding.EncodeToString(unencodedPassword)
	hash := fmt.Sprintf("%s$%d$%d$%d$%d$%s$%s", passwordType, argon2Time, argon2Memory, argon2Threads, argon2KeyLen, salt, encodedPassword)
	return hash, nil
}

// Compare compares a password with a hash.
func Compare(hash, password string) (bool, error) {
	if len(hash) == 0 || len(password) == 0 {
		return false, errors.New("Arguments cannot be empty")
	}

	hashParts := strings.Split(hash, "$")
	if len(hashParts) != 7 {
		return false, errors.New("Invalid password hash")
	}

	passwordType := hashParts[0]
	argon2Time, _ := strconv.Atoi(hashParts[1])
	argon2Memory, _ := strconv.Atoi(hashParts[2])
	argon2Threads, _ := strconv.Atoi(hashParts[3])
	argon2KeyLen, _ := strconv.Atoi(hashParts[4])
	salt := []byte(hashParts[5])
	encodedPassword, _ := base64.StdEncoding.DecodeString(hashParts[6])

	var calculatedPassword []byte
	switch passwordType {
	case "argon2id":
		calculatedPassword = argon2.IDKey([]byte(password), salt, uint32(argon2Time), uint32(argon2Memory), uint8(argon2Threads), uint32(argon2KeyLen))
	case "argon2i", "argon2":
		calculatedPassword = argon2.Key([]byte(password), salt, uint32(argon2Time), uint32(argon2Memory), uint8(argon2Threads), uint32(argon2KeyLen))
	default:
		return false, errors.Errorf("Invalid password hash(type: %s)", passwordType)
	}

	if subtle.ConstantTimeCompare(encodedPassword, calculatedPassword) != 1 {
		return false, errors.New("Password does not match")
	}

	return true, nil
}
