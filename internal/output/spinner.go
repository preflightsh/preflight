package output

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Spinner is a lightweight terminal progress indicator. Writes to stderr
// so it never pollutes stdout (which may be piped or captured). Disabled
// automatically when stderr is not a terminal, on NO_COLOR, TERM=dumb,
// and when Start is never called. It used to look at stdout, so
// `preflight scan 2>scan.log` filled the log with escape frames while
// `preflight scan >report.txt` showed no progress at all. All methods are no-ops on a zero-value Spinner, so
// callers can hold a *Spinner without nil checks.
type Spinner struct {
	mu       sync.Mutex
	msg      string
	done     chan struct{}
	exited   chan struct{}
	stopOnce sync.Once
	enabled  bool
}

func NewSpinner() *Spinner {
	return &Spinner{
		done:    make(chan struct{}),
		exited:  make(chan struct{}),
		enabled: fancyTerminal(os.Stderr),
	}
}

// Start launches the render loop in a goroutine. Safe to call on a
// disabled spinner; it just no-ops.
func (s *Spinner) Start(initial string) {
	if !s.enabled {
		return
	}
	s.msg = initial
	go s.run()
}

func (s *Spinner) run() {
	defer close(s.exited)
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	i := 0
	for {
		select {
		case <-s.done:
			fmt.Fprint(os.Stderr, "\r\033[2K")
			return
		case <-ticker.C:
			s.mu.Lock()
			msg := s.msg
			s.mu.Unlock()
			fmt.Fprintf(os.Stderr, "\r\033[2K%s %s", frames[i], msg)
			i = (i + 1) % len(frames)
		}
	}
}

// Update changes the message shown next to the spinner frame. Safe to
// call from any goroutine.
func (s *Spinner) Update(msg string) {
	if !s.enabled {
		return
	}
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

// Stop halts rendering, clears the spinner line, and blocks until the
// render goroutine has exited. Safe to call multiple times.
func (s *Spinner) Stop() {
	if !s.enabled {
		return
	}
	s.stopOnce.Do(func() {
		close(s.done)
		<-s.exited
	})
}
