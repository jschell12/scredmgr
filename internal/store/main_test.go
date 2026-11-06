package store

import (
	"os"
	"testing"
)

// Tests give each case its own temp home, and the first HomeDir call in each
// would run `tmutil addexclusion`, seconds apiece on a CI runner. Temp dirs
// are not backed up anyway.
func TestMain(m *testing.M) {
	SetTimeMachineExcluder(func(string) {})
	os.Exit(m.Run())
}
