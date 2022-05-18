# PasswordHashing - Light generating and comparing password hashing with argon2, better Bcrypt

[![PkgGoDev](https://pkg.go.dev/badge/github.com/go-zoox/password-hashing)](https://pkg.go.dev/github.com/go-zoox/password-hashing)
[![Build Status](https://github.com/go-zoox/password-hashing/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/go-zoox/password-hashing/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-zoox/password-hashing)](https://goreportcard.com/report/github.com/go-zoox/password-hashing)
[![Coverage Status](https://coveralls.io/repos/github/go-zoox/password-hashing/badge.svg?branch=master)](https://coveralls.io/github/go-zoox/password-hashing?branch=master)
[![GitHub issues](https://img.shields.io/github/issues/go-zoox/password-hashing.svg)](https://github.com/go-zoox/password-hashing/issues)
[![Release](https://img.shields.io/github/tag/go-zoox/password-hashing.svg?label=Release)](https://github.com/go-zoox/password-hashing/tags)

## Installation
To install the package, run:
```bash
go get github.com/go-zoox/password-hashing
```

## Getting Started

```go
import (
  "testing"
  "github.com/go-zoox/password-hashing"
)

func main(t *testing.T) {
	password := "the-real-password"
	// generate a hash
	hash, err := Generate(password)
	if err != nil {
		log.Panic("Failed to generate hash")
	}

	// compare hash with password
	isValid, err := Compare(hash, password)
	if err != nil {
		log.Panic("Failed to compare hash")
	}

	if !isValid {
		log.Panic("Hash is not valid")
	}
}
```

## Inspired By
* [raja/argon2pw](https://github.com/raja/argon2pw) - Argon2 password hashing package for go with constant time hash comparison
* [andskur/argon2-hashing](https://github.com/andskur/argon2-hashing) - A light package for generating and comparing password hashing with argon2 in Go
* [密码哈希的方法：PBKDF2，Scrypt，Bcrypt 和 ARGON2 - 司徒公子](https://zhuanlan.zhihu.com/p/113971205)

## License
GoZoox is released under the [MIT License](./LICENSE).
