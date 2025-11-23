package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	NonceSize         = 12
	KeySize           = 32
	HMACSize          = 32
	SessionTimeout    = 30 * time.Minute
	DefaultMessageTTL = 5 * time.Minute
)

// Session stores encryption keys and metadata
type Session struct {
	SharedSecret []byte
	EncKey       []byte
	MacKey       []byte
	CreatedAt    time.Time
	LastUsed     time.Time
	Nonce        uint64
	Metadata     map[string]string
	SessionTTL   time.Duration
	MessageTTL   time.Duration
	mu           sync.Mutex
}

// EncryptedMessage structure for encrypted data
type EncryptedMessage struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	HMAC       []byte `json:"hmac"`
	Timestamp  int64  `json:"timestamp"`
}

// HandshakeRequest from client
type HandshakeRequest struct {
	ClientPublicKey []byte `json:"client_public_key"`
	DeviceID        string `json:"device_id"`
	DeviceSignature []byte `json:"device_signature"`
	UserToken       string `json:"user_token,omitempty"`
	Timestamp       int64  `json:"timestamp"`
}

// HandshakeResponse to client
type HandshakeResponse struct {
	ServerPublicKey []byte `json:"server_public_key"`
	SessionID       []byte `json:"session_id"`
	DeviceID        string `json:"device_id,omitempty"`
	ExpiresAt       int64  `json:"expires_at"`
	Timestamp       int64  `json:"timestamp"`
}

// DeriveKeys uses HKDF to derive encryption and MAC keys
func DeriveKeys(secret []byte) (encKey, macKey []byte, err error) {
	kdf := hkdf.New(sha512.New, secret, nil, []byte("secure-communication-v1"))

	encKey = make([]byte, KeySize)
	if _, err := io.ReadFull(kdf, encKey); err != nil {
		return nil, nil, err
	}

	macKey = make([]byte, KeySize)
	if _, err := io.ReadFull(kdf, macKey); err != nil {
		return nil, nil, err
	}

	return encKey, macKey, nil
}

// ComputeHMAC generates HMAC-SHA256
func ComputeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifies HMAC in constant time
func VerifyHMAC(key, data, mac []byte) bool {
	expected := ComputeHMAC(key, data)
	return hmac.Equal(expected, mac)
}

// GenerateKeyPair generates ECDH key pair
func GenerateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, privKey.PublicKey(), nil
}

// PerformECDH performs Elliptic Curve Diffie-Hellman
func PerformECDH(privateKey *ecdh.PrivateKey, publicKeyBytes []byte) ([]byte, error) {
	publicKey, err := privateKey.PublicKey().Curve().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	return privateKey.ECDH(publicKey)
}

// Encrypt encrypts and signs message
func (s *Session) Encrypt(plaintext []byte) (*EncryptedMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(s.EncKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// Create message
	timestamp := time.Now().Unix()
	msg := &EncryptedMessage{
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Timestamp:  timestamp,
	}

	// Compute HMAC over nonce + ciphertext + timestamp
	data := append(msg.Nonce, msg.Ciphertext...)
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	data = append(data, timestampBytes...)
	msg.HMAC = ComputeHMAC(s.MacKey, data)

	s.LastUsed = time.Now()
	s.Nonce++
	return msg, nil
}

// Decrypt decrypts and verifies message
func (s *Session) Decrypt(msg *EncryptedMessage) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify timestamp within allowed window
	msgWindow := s.MessageTTL
	if msgWindow <= 0 {
		msgWindow = DefaultMessageTTL
	}
	msgTime := time.Unix(msg.Timestamp, 0)
	delta := time.Since(msgTime)
	if delta > msgWindow || delta < -msgWindow {
		return nil, errors.New("message expired")
	}

	// Verify HMAC
	data := append(msg.Nonce, msg.Ciphertext...)
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(msg.Timestamp))
	data = append(data, timestampBytes...)

	if !VerifyHMAC(s.MacKey, data, msg.HMAC) {
		return nil, errors.New("HMAC verification failed")
	}

	// Decrypt with AES-GCM
	block, err := aes.NewCipher(s.EncKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, msg.Nonce, msg.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	s.LastUsed = time.Now()
	return plaintext, nil
}

// IsExpired checks if session has expired
func (s *Session) IsExpired() bool {
	ttl := s.SessionTTL
	if ttl <= 0 {
		ttl = SessionTimeout
	}
	return time.Since(s.LastUsed) > ttl
}
