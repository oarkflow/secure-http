package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func decodeKeyMaterial(input string) ([]byte, error) {
    trimmed := strings.TrimSpace(input)
    if trimmed == "" {
        return nil, fmt.Errorf("secret value is empty")
    }
    switch {
    case strings.HasPrefix(trimmed, "base64:"):
        decoded, err := base64.StdEncoding.DecodeString(trimmed[7:])
        if err != nil {
            return nil, fmt.Errorf("invalid base64 secret: %w", err)
        }
        return decoded, nil
    case strings.HasPrefix(trimmed, "hex:"):
        decoded, err := hex.DecodeString(trimmed[4:])
        if err != nil {
            return nil, fmt.Errorf("invalid hex secret: %w", err)
        }
        return decoded, nil
    default:
        return []byte(trimmed), nil
    }
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
    value = strings.TrimSpace(value)
    if value == "" {
        return fallback, nil
    }
    d, err := time.ParseDuration(value)
    if err != nil {
        return 0, fmt.Errorf("invalid duration %q: %w", value, err)
    }
    return d, nil
}

func parseOptionalTime(value string) (time.Time, error) {
    value = strings.TrimSpace(value)
    if value == "" {
        return time.Time{}, nil
    }
    ts, err := time.Parse(time.RFC3339, value)
    if err != nil {
        return time.Time{}, fmt.Errorf("invalid timestamp %q: %w", value, err)
    }
    return ts, nil
}

func normalizeMethodSet(methods []string) map[string]struct{} {
    if len(methods) == 0 {
        return nil
    }
    set := make(map[string]struct{}, len(methods))
    for _, m := range methods {
        m = strings.ToUpper(strings.TrimSpace(m))
        if m == "" {
            continue
        }
        set[m] = struct{}{}
    }
    if len(set) == 0 {
        return nil
    }
    return set
}
