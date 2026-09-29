//go:build !windows

package owner

func isSizeRace(error) bool { return false }
