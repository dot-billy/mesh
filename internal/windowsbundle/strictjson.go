package windowsbundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func marshalPackage(metadata Package) ([]byte, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode package metadata: %w", err)
	}
	return append(raw, '\n'), nil
}

func parsePackage(raw []byte) (Package, error) {
	var metadata Package
	if len(raw) == 0 || int64(len(raw)) > maxPackageJSONSize {
		return metadata, fmt.Errorf("package.json size must be between 1 and %d bytes", maxPackageJSONSize)
	}
	if err := validateJSONSyntax(raw); err != nil {
		return metadata, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return metadata, fmt.Errorf("decode package.json: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return metadata, fmt.Errorf("decode package.json: %w", err)
	}
	if _, err := validatePackage(metadata); err != nil {
		return metadata, err
	}
	canonical, err := marshalPackage(metadata)
	if err != nil {
		return metadata, err
	}
	if !bytes.Equal(raw, canonical) {
		return metadata, errors.New("package.json is not in canonical encoding")
	}
	return metadata, nil
}

func validateJSONSyntax(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("package.json is not valid UTF-8")
	}
	if err := validateJSONSurrogates(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("trailing JSON: %w", err)
		}
		return fmt.Errorf("trailing JSON value beginning with %v", token)
	}
	return nil
}

func validateJSONSurrogates(raw []byte) error {
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
					return errors.New("package.json contains an unpaired high UTF-16 surrogate escape")
				}
				low, ok := parseHexQuad(raw[index+3 : index+7])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("package.json contains an unpaired high UTF-16 surrogate escape")
				}
				index += 6
			case value >= 0xdc00 && value <= 0xdfff:
				return errors.New("package.json contains an unpaired low UTF-16 surrogate escape")
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
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
