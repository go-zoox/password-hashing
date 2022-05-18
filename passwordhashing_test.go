package passwordhashing

import (
	"strings"
	"testing"
)

func TestPasswordHashingGenerate(t *testing.T) {
	testcases := []struct {
		name         string
		password     string
		hashSegments int
		hashLength   int
		wantErr      bool
	}{
		{name: "Should Work", password: "Password1", hashSegments: 7, hashLength: 111, wantErr: false},
		{name: "Should Fail", password: "", hashSegments: 1, hashLength: 0, wantErr: true},
		{name: "Should Work 2", password: "gS</5Tu>3@(<FCtY", hashSegments: 7, hashLength: 111, wantErr: false},
		{name: "Should Work 3", password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, hashSegments: 7, hashLength: 111, wantErr: false},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Generate(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			hashSegments := strings.Split(got, "$")
			if len(hashSegments) != tt.hashSegments {
				t.Errorf("Generate() hashSegments = %v, want %v", len(hashSegments), tt.hashSegments)
			}

			if len(got) != tt.hashLength {
				t.Errorf("Generate() hashLength = %v, want %v", len(got), tt.hashLength)
			}
		})
	}
}

func TestCompareHashWithPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		hash     string
		isValid  bool
		wantErr  bool
	}{
		{name: "Should Work 1", hash: `argon2id$1$65536$4$32$Kmmw5Rb2JicAHlGL+yIvE5AlamkCZimr9vEqqgxj4pU=$BJzVSk9azcO/6Po+x6qWwFUFZlBy9sUsp4eSDzv20sU=`, password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: true, wantErr: false},
		{name: "Should Not Work 1", hash: `argon2id$1$65536$4$32$IJwacnund802ogLkPaNTHuspQBrAwKlySItlOcKvpaI=$eGVF7y4cyufIVajJFYf/yoRQp8BJS+Qplx5bYXSXX2A=`, password: `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: false, wantErr: true},
		{name: "Should Not Work 2", hash: ``, password: ``, isValid: false, wantErr: true},
		{name: "Should Not Work 3", hash: `badHash`, password: ``, isValid: false, wantErr: true},
		{name: "Should Work 2", hash: `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$oLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: true, wantErr: false},
		{name: "Should Not Work 4", hash: `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$XLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, password: `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: false, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compare(tt.hash, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compare() error = %v, wantErr %v", err, tt.wantErr)
				t.Errorf("hash is %v", got)
				return
			}
			if got != tt.isValid {
				t.Errorf("Compare() = %v, want %v", got, tt.isValid)
			}
		})
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "the-real-password"
	// generate a hash
	hash, err := Generate(password)
	if err != nil {
		t.Errorf("Failed to generate hash")
	}

	// compare hash with password
	isValid, err := Compare(hash, password)
	if err != nil {
		t.Errorf("Failed to compare hash")
	}

	if !isValid {
		t.Errorf("Hash is not valid")
	}
}
