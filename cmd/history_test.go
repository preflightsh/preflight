package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/preflightsh/preflight/internal/dashboard"
	"github.com/preflightsh/preflight/internal/output"
)

// The agent skill tells agents to check the version fields of history
// JSON, which had none. They are added beside the existing keys.
func TestHistoryJSONCarriesVersions(t *testing.T) {
	for name, v := range map[string]any{
		"list": map[string]any{"runs": []dashboard.RunSummary{{ID: "r1"}}},
		"run":  &dashboard.RunDetail{ID: "r2", ProjectName: "demo"},
	} {
		var buf bytes.Buffer
		if err := writeHistoryJSON(&buf, v); err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["schema_version"] != float64(output.SchemaVersion) || got["cli_version"] != version {
			t.Errorf("%s: versions missing: %v", name, got)
		}
		if name == "list" && got["runs"] == nil {
			t.Errorf("list lost its runs key: %v", got)
		}
		if name == "run" && (got["id"] != "r2" || got["project_name"] != "demo") {
			t.Errorf("run lost its fields: %v", got)
		}
	}
}
