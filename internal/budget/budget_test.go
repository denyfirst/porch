package budget

import (
	"context"
	"testing"
	"time"
)

// The questions after a measurement end short of the caller's deadline, never
// after it, and a caller with no deadline imposes none.
func TestTheQuestionsAfterAMeasurementEndShortOfTheDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want, _ := parent.Deadline()

	short, stop := ShortOf(parent, Reserve)
	defer stop()
	got, ok := short.Deadline()
	if !ok || !got.Equal(want.Add(-Reserve)) {
		t.Errorf("deadline %v, want %v before the caller's %v", got, Reserve, want)
	}

	// Within the reserve already: done at once.
	near, cancelNear := context.WithTimeout(context.Background(), Reserve/2)
	defer cancelNear()
	done, stopDone := ShortOf(near, Reserve)
	defer stopDone()
	select {
	case <-done.Done():
	case <-time.After(time.Second):
		t.Error("a deadline already inside the reserve gave a context that is not done")
	}

	// No deadline, none added, and cancelling the parent still ends it.
	free, cancelFree := context.WithCancel(context.Background())
	unbounded, stopUnbounded := ShortOf(free, Reserve)
	defer stopUnbounded()
	if _, ok := unbounded.Deadline(); ok {
		t.Error("a caller with no deadline was given one")
	}
	cancelFree()
	if unbounded.Err() == nil {
		t.Error("cancelling the caller did not end the shortened context")
	}
}

// A third party asked before the measurement gets half of what is left, and
// the measurement the rest.
func TestAThirdPartyAskedFirstLeavesHalfTheTime(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx, done := Half(parent)
	defer done()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("half a deadline is no deadline")
	}
	if left := time.Until(deadline); left > 5*time.Second || left < 4*time.Second {
		t.Errorf("the third party was given %v of 10s, want about half", left)
	}

	// No deadline to halve is no deadline added.
	free, stop := Half(context.Background())
	defer stop()
	if _, ok := free.Deadline(); ok {
		t.Error("a context with no deadline was given one")
	}
}
