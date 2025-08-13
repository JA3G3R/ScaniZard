package main // or a `types` package if you want separation

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"github.com/JA3G3R/scanizard/types"
)


func PrintFindings(findings []types.Finding, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	default:
		// default to table output
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "SEVERITY\tRULE\tFILE:LINE\tDETAILS")
		for _, f := range findings {
			fmt.Fprintf(w, "%s\t%s\t%s:%d\t%s\n",
				f.Severity, f.Rule, f.File, f.Line, f.Details)
		}
		w.Flush()
	}
}
