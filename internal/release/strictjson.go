package release

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// ValidateStrictJSON applies the release parser's duplicate-field, Unicode,
// delimiter, and single-value rules without decoding any schema semantics.
// Callers must still enforce an independent byte bound before invoking it.
func ValidateStrictJSON(raw []byte) error {
	return validateJSONSyntax(raw)
}

func validateJSONSyntax(raw []byte) error {
	if err := validateJSONUnicode(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("trailing JSON: %w", err)
		}
		return fmt.Errorf("trailing JSON value beginning with %v", token)
	}
	return nil
}

// encoding/json replaces invalid UTF-8 and unpaired UTF-16 surrogate escapes
// with U+FFFD. Release metadata instead rejects those non-canonical inputs so
// different parsers cannot authenticate different logical text from the same
// signed bytes.
func validateJSONUnicode(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("invalid JSON: input is not valid UTF-8")
	}
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			index++
			if raw[index] != 'u' || index+4 >= len(raw) {
				continue
			}
			value, ok := parseHexQuad(raw[index+1 : index+5])
			if !ok {
				continue
			}
			index += 4
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return fmt.Errorf("invalid JSON: unpaired high UTF-16 surrogate escape")
				}
				low, ok := parseHexQuad(raw[index+3 : index+7])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("invalid JSON: unpaired high UTF-16 surrogate escape")
				}
				index += 6
			case value >= 0xdc00 && value <= 0xdfff:
				return fmt.Errorf("invalid JSON: unpaired low UTF-16 surrogate escape")
			}
		}
	}
	return nil
}

func parseHexQuad(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, character := range raw {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid object terminator")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func decodeStrict(raw []byte, output any) error {
	if err := validateJSONSyntax(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	return nil
}

func exactObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowedSet[key]; !ok {
			return nil, fmt.Errorf("unknown field %q", key)
		}
	}
	return object, nil
}

func requireFields(object map[string]json.RawMessage, fields ...string) error {
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return fmt.Errorf("missing field %q", field)
		}
	}
	return nil
}
