package g8

import (
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(2)
	if rl.maximumExecutionsPerSecond != 2 {
		t.Errorf("expected maximumExecutionsPerSecond to be %d, got %d", 2, rl.maximumExecutionsPerSecond)
	}
	if rl.executionsLeftInWindow != 2 {
		t.Errorf("expected executionsLeftInWindow to be %d, got %d", 2, rl.executionsLeftInWindow)
	}
	// First execution: should not be rate limited
	if notRateLimited := rl.Try(); !notRateLimited {
		t.Error("expected Try to return true")
	}
	if rl.maximumExecutionsPerSecond != 2 {
		t.Errorf("expected maximumExecutionsPerSecond to be %d, got %d", 2, rl.maximumExecutionsPerSecond)
	}
	if rl.executionsLeftInWindow != 1 {
		t.Errorf("expected executionsLeftInWindow to be %d, got %d", 1, rl.executionsLeftInWindow)
	}
	// Second execution: should not be rate limited
	if notRateLimited := rl.Try(); !notRateLimited {
		t.Error("expected Try to return true")
	}
	if rl.maximumExecutionsPerSecond != 2 {
		t.Errorf("expected maximumExecutionsPerSecond to be %d, got %d", 2, rl.maximumExecutionsPerSecond)
	}
	if rl.executionsLeftInWindow != 0 {
		t.Errorf("expected executionsLeftInWindow to be %d, got %d", 0, rl.executionsLeftInWindow)
	}
	// Third execution: should be rate limited
	if notRateLimited := rl.Try(); notRateLimited {
		t.Error("expected Try to return false")
	}
	if rl.maximumExecutionsPerSecond != 2 {
		t.Errorf("expected maximumExecutionsPerSecond to be %d, got %d", 2, rl.maximumExecutionsPerSecond)
	}
	if rl.executionsLeftInWindow != 0 {
		t.Errorf("expected executionsLeftInWindow to be %d, got %d", 0, rl.executionsLeftInWindow)
	}
}

func TestRateLimiter_Try(t *testing.T) {
	rl := NewRateLimiter(5)
	for i := 0; i < 20; i++ {
		notRateLimited := rl.Try()
		if i < 5 {
			if !notRateLimited {
				t.Fatal("expected to not be rate limited")
			}
		} else {
			if notRateLimited {
				t.Fatal("expected to be rate limited")
			}
		}
	}
}

func TestRateLimiter_TryAlwaysUnderRateLimit(t *testing.T) {
	rl := NewRateLimiter(20)
	for i := 0; i < 45; i++ {
		notRateLimited := rl.Try()
		if !notRateLimited {
			t.Fatal("expected to not be rate limited")
		}
		time.Sleep(51 * time.Millisecond)
	}
}
