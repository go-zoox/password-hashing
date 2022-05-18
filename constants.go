package passwordhashing

import "runtime"

const (
	passwordType = "argon2id"
	saltLen      = 32
	argon2KeyLen = 32
	argon2Time   = 1
	argon2Memory = 64 * 1024
)

var argon2Threads = uint8(runtime.NumCPU())
