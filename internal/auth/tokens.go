package auth

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
	"sync"
)

// TokenStore holds a set of allowed bearer tokens.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]struct{}
	path   string
}

// NewTokenStore returns an empty TokenStore.
func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]struct{})}
}

// LoadTokens reads bearer tokens from a text file, one token per line, and
// returns a new TokenStore. Lines beginning with '#' and blank lines are
// ignored. The path is remembered for subsequent Reload calls.
func LoadTokens(path string) (*TokenStore, error) {
	ts := &TokenStore{path: path}
	if err := ts.load(path); err != nil {
		return nil, fmt.Errorf("loading tokens file %q: %w", path, err)
	}
	return ts, nil
}

func (s *TokenStore) load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			s.tokens = make(map[string]struct{})
			s.mu.Unlock()
			return nil
		}
		return err
	}
	defer f.Close()

	tokens := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.tokens = tokens
	s.mu.Unlock()
	return nil
}

// Reload re-reads the tokens file. The path used is the one passed to
// LoadTokens; if this TokenStore was created with NewTokenStore, path must be
// provided explicitly.
func (s *TokenStore) Reload(path string) error {
	if err := s.load(path); err != nil {
		return fmt.Errorf("reloading tokens file %q: %w", path, err)
	}
	return nil
}

// Allow reports whether token is present in the store.
// Uses constant-time comparison to prevent timing-based enumeration of valid tokens.
// Iterates all tokens regardless of match to keep timing independent of validity.
func (s *TokenStore) Allow(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tokenHash := sha256.Sum256([]byte(token))
	var result int
	for t := range s.tokens {
		storedHash := sha256.Sum256([]byte(t))
		result |= subtle.ConstantTimeCompare(tokenHash[:], storedHash[:])
	}
	return result == 1
}

// IsEmpty reports whether the store contains no tokens.
func (s *TokenStore) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens) == 0
}
