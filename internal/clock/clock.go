// Package clock defines the time boundary used by policy workers and caches.
package clock

import "time"

// Clock supplies current time and cancellable timers.
type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}
