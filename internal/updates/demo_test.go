//go:build demo

package updates

import (
	"context"
	"errors"
	"testing"
)

// The demonstration connects only to hosts this project owns, and GitHub is
// not one: a check refuses before anything is dialled.
func TestTheDemonstrationDoesNotCheck(t *testing.T) {
	c := &Checker{Base: "https://192.0.2.1/"}
	if _, err := c.Check(context.Background()); !errors.Is(err, ErrDemo) {
		t.Errorf("the demonstration checked: %v", err)
	}
}
