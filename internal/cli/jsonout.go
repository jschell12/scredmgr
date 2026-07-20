package cli

import (
	"encoding/json"
	"os"

	"github.com/jschell12/scredmanager/internal/safety"
)

// envelope is the stable --json contract (consumed by the GUI in M7).
type envelope struct {
	SchemaVersion int    `json:"schemaVersion"`
	OK            bool   `json:"ok"`
	Data          any    `json:"data,omitempty"`
	Error         string `json:"error,omitempty"`
}

func emit(data any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(envelope{SchemaVersion: 1, OK: true, Data: data})
}

func emitError(err error) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(envelope{SchemaVersion: 1, OK: false, Error: safety.Redact(err.Error())})
}
