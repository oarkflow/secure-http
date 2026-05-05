package crypto

import (
	"errors"
	"testing"
	"time"
)

func TestSessionDecryptRejectsReplay(t *testing.T) {
	session := &Session{
		EncKey:       []byte("12345678901234567890123456789012"),
		MacKey:       []byte("abcdefabcdefabcdefabcdefabcdef12"),
		LastUsed:     time.Now(),
		MessageTTL:   time.Minute,
		SeenMessages: make(map[string]time.Time),
	}

	msg, err := session.Encrypt([]byte(`{"ok":true}`))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if _, err := session.Decrypt(msg); err != nil {
		t.Fatalf("Decrypt() first error = %v", err)
	}
	if _, err := session.Decrypt(msg); !errors.Is(err, ErrMessageReplay) {
		t.Fatalf("Decrypt() replay error = %v, want %v", err, ErrMessageReplay)
	}
}
