package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
)

const (
	maxDarwinProcessArguments = 64
	maxDarwinProcessArgBytes  = 1 << 20
	maxDarwinProcessPathBytes = 1024
)

// parseDarwinProcessArguments decodes the KERN_PROCARGS2 result: native argc,
// one bare executable path, alignment NULs, and exactly argc C strings.
// Environment bytes, when the kernel elects to disclose them, are outside the
// returned argv slice and never participate in identity matching.
func parseDarwinProcessArguments(raw []byte) (string, []string, error) {
	if len(raw) < 6 || len(raw) > maxDarwinProcessArgBytes {
		return "", nil, errors.New("Darwin process-argument result is outside the accepted bound")
	}
	argc := int(int32(binary.LittleEndian.Uint32(raw[:4])))
	if argc < 1 || argc > maxDarwinProcessArguments {
		return "", nil, fmt.Errorf("Darwin process argc %d is outside the accepted bound", argc)
	}
	cursor := 4
	executable, next, err := nextDarwinCString(raw, cursor, maxDarwinProcessPathBytes)
	if err != nil || executable == "" || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return "", nil, errors.New("Darwin process executable path is invalid")
	}
	cursor = next
	for cursor < len(raw) && raw[cursor] == 0 {
		cursor++
	}
	arguments := make([]string, 0, argc)
	for index := 0; index < argc; index++ {
		argument, next, err := nextDarwinCString(raw, cursor, maxDarwinProcessPathBytes)
		if err != nil {
			return "", nil, fmt.Errorf("Darwin process argument %d is invalid: %w", index, err)
		}
		arguments = append(arguments, argument)
		cursor = next
	}
	return executable, arguments, nil
}

func validateDarwinProcessArguments(raw []byte, resolvedBinary string, expected []string) error {
	executable, arguments, err := parseDarwinProcessArguments(raw)
	if err != nil {
		return err
	}
	if executable != resolvedBinary {
		return errors.New("Darwin child executable path differs from the authenticated release")
	}
	if !reflect.DeepEqual(arguments, expected) {
		return errors.New("Darwin child argument vector differs from the supervised command")
	}
	return nil
}

func nextDarwinCString(raw []byte, start, maximum int) (string, int, error) {
	if start < 0 || start >= len(raw) {
		return "", 0, errors.New("missing NUL-terminated string")
	}
	limit := start + maximum + 1
	if limit > len(raw) {
		limit = len(raw)
	}
	for index := start; index < limit; index++ {
		if raw[index] == 0 {
			return string(raw[start:index]), index + 1, nil
		}
	}
	return "", 0, errors.New("NUL-terminated string exceeds its bound")
}
