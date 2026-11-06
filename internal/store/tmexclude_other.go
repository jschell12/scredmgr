//go:build !darwin

package store

func excludeFromTimeMachine(_ string) {}

// SetTimeMachineExcluder is a no-op off darwin (tests only).
func SetTimeMachineExcluder(func(dir string)) {}
