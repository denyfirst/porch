package updates

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Settings keeps the one choice this package has: whether to check daily.
//
// A small file beside the access file, written whole and renamed into place
// so a crash leaves the old choice or the new one and never half of either,
// readable by this user alone. Off when the file is missing, unreadable or
// says anything else: the check that asks GitHub something is the one that
// has to be chosen, never the one a broken file falls into.
type Settings struct {
	// Path is the file. Empty keeps the choice in memory, for tests.
	Path string

	mu    sync.Mutex
	daily bool
}

const maxSettings = 1 << 10

type settingsFile struct {
	Daily bool `json:"daily"`
}

// Load reads the file. A missing one is the default, off.
func (s *Settings) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.daily = false
	if s.Path == "" {
		return nil
	}
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("updates: the settings file could not be read")
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxSettings))
	dec.DisallowUnknownFields()
	var got settingsFile
	if err := dec.Decode(&got); err != nil {
		return errors.New("updates: the settings file is not one this version wrote")
	}
	s.daily = got.Daily
	return nil
}

// Daily reports the choice.
func (s *Settings) Daily() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.daily
}

// SetDaily records the choice, on disk first: a choice that did not reach the
// disk is not reported as made.
func (s *Settings) SetDaily(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Path != "" {
		body, err := json.Marshal(settingsFile{Daily: on})
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".updates-*.tmp")
		if err != nil {
			return errors.New("updates: the choice could not be kept")
		}
		name := tmp.Name()
		_, werr := tmp.Write(body)
		serr := tmp.Sync()
		cerr := tmp.Close()
		if werr != nil || serr != nil || cerr != nil {
			_ = os.Remove(name)
			return errors.New("updates: the choice could not be kept")
		}
		if err := os.Chmod(name, 0o600); err != nil {
			_ = os.Remove(name)
			return errors.New("updates: the choice could not be kept")
		}
		if err := os.Rename(name, s.Path); err != nil {
			_ = os.Remove(name)
			return errors.New("updates: the choice could not be kept")
		}
	}
	s.daily = on
	return nil
}
