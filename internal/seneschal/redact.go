package seneschal

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
)

var (
	skPattern     = regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)
	bearerPattern = regexp.MustCompile(`Bearer\s+[A-Za-z0-9\-._~+/]{20,}`)
	googlePattern = regexp.MustCompile(`AIzaSy[A-Za-z0-9\-_]{33}`)
	genericPattern = regexp.MustCompile(`[A-Za-z0-9]{32,}`)
)

// RedactKeys scans arbitrary structs/maps/slices/strings and redacts sensitive patterns
func RedactKeys(input interface{}) interface{} {
	if input == nil {
		return nil
	}
	
	// Convert to JSON and back for generic reflection processing
	b, err := json.Marshal(input)
	if err != nil {
		return input
	}

	var parsed interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return input
	}
	
	parsed = redactNode(parsed, "")
	
	// Marshal and unmarshal back to original type (this is expensive but ensures immutability and complete coverage)
	// For performance, we'll return the JSON []byte in actual systems, but for the interface we can return the redacted map
	// However, if the caller expects the specific type, we need to deserialize it back.
	b2, _ := json.Marshal(parsed)
	
	val := reflect.New(reflect.TypeOf(input))
	if err := json.Unmarshal(b2, val.Interface()); err == nil {
		return val.Elem().Interface()
	}

	return input
}

func redactNode(node interface{}, keyName string) interface{} {
	switch v := node.(type) {
	case string:
		return redactString(v, keyName)
	case []interface{}:
		for i, item := range v {
			v[i] = redactNode(item, "")
		}
		return v
	case map[string]interface{}:
		for k, val := range v {
			v[k] = redactNode(val, k)
		}
		return v
	default:
		return v
	}
}

func redactString(s string, keyName string) string {
	res := s
	res = skPattern.ReplaceAllString(res, "[REDACTED]")
	res = bearerPattern.ReplaceAllString(res, "Bearer [REDACTED]")
	res = googlePattern.ReplaceAllString(res, "[REDACTED]")

	k := strings.ToLower(keyName)
	if strings.Contains(k, "key") || strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "password") {
		res = genericPattern.ReplaceAllString(res, "[REDACTED]")
	}

	return res
}
