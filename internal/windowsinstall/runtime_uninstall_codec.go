package windowsinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maximumWindowsRuntimeUninstallJournalBytes = 160 << 10

func MarshalWindowsRuntimeUninstallJournal(journal WindowsRuntimeUninstallJournal) ([]byte, error) {
	if err := journal.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return nil, fmt.Errorf("encode Windows runtime-uninstall journal: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maximumWindowsRuntimeUninstallJournalBytes {
		return nil, errors.New("Windows runtime-uninstall journal exceeds its size bound")
	}
	return raw, nil
}

func ParseWindowsRuntimeUninstallJournal(raw []byte) (WindowsRuntimeUninstallJournal, error) {
	if len(raw) < 2 || len(raw) > maximumWindowsRuntimeUninstallJournalBytes {
		return WindowsRuntimeUninstallJournal{}, errors.New("Windows runtime-uninstall journal is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal WindowsRuntimeUninstallJournal
	if err := decoder.Decode(&journal); err != nil {
		return WindowsRuntimeUninstallJournal{}, fmt.Errorf("decode Windows runtime-uninstall journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return WindowsRuntimeUninstallJournal{}, errors.New("Windows runtime-uninstall journal contains trailing data")
	}
	canonical, err := MarshalWindowsRuntimeUninstallJournal(journal)
	if err != nil {
		return WindowsRuntimeUninstallJournal{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return WindowsRuntimeUninstallJournal{}, errors.New("Windows runtime-uninstall journal is not canonical")
	}
	return journal, nil
}
