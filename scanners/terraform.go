package scanners

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/JA3G3R/scanizard/types"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func ScanTerraform(folder string) []types.Finding {
	parser := hclparse.NewParser()
	var findings []types.Finding
	err := filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".tf") {
			return nil
		}

		file, diag := parser.ParseHCLFile(path)
		if diag.HasErrors() {
			fmt.Fprintf(os.Stderr, "Parse error in %s: %s\n", path, diag.Error())
			return nil
		}

		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			// Try to convert
			if b, convErr := hclsyntax.ParseConfig(file.Bytes, path, hcl.InitialPos); convErr == nil {
				body = b.Body.(*hclsyntax.Body)
			} else {
				fmt.Fprintf(os.Stderr, "Cannot get syntax body for %s: %v\n", path, convErr)
				return nil
			}
		}

		// Walk top-level blocks
		for _, blk := range body.Blocks {
			switch blk.Type {
			case "resource":
				if len(blk.Labels) < 2 {
					continue
				}
				rType := blk.Labels[0]
				rName := blk.Labels[1]
				blockRef := fmt.Sprintf(`resource.%s.%s`, rType, rName)

				if resourceTypesWithPolicyJSON[rType] {
					if attr, ok := blk.Body.Attributes["policy"]; ok {
						if lit := tryExtractStaticString(attr.Expr); lit != "" {
							findings = append(findings, analyzeJSONPolicy(lit, path, blockRef, attr.Range())...)
						} else {
							// Could be jsonencode(...) or interpolation
							findings = append(findings, types.Finding{
								Scanner:     "terraform",
								Rule:        "unknown_dynamic_policy",
								Severity:    "HIGH",
								File:        path,
								Line:        attr.Range().Start.Line,
								Column:      attr.Range().Start.Column,
								BlockRef:    blockRef,
								StatementID: "",
								Details:     "Policy attribute is dynamic (jsonencode/interpolation). Could not statically analyze.",
							})
						}
					}
				}

			case "data":
				if len(blk.Labels) < 2 {
					continue
				}
				dType := blk.Labels[0]
				dName := blk.Labels[1]
				blockRef := fmt.Sprintf(`data.%s.%s`, dType, dName)

				if dType == "aws_iam_policy_document" {
					findings = append(findings, analyzeIAMPolicyDocumentBlock(blk, path, blockRef)...)
				}
			}
		}

		return nil

	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Walk error: %v\n", err)
		return nil
	}

	return nil

}

// ---------------------------
// Policy JSON types & helpers
// ---------------------------

type policyDoc struct {
	Version   string       `json:"Version"`
	Statement []policyStmt `json:"Statement"`
}

type strOrList []string

func (s *strOrList) UnmarshalJSON(b []byte) error {
	// Accept either "string" or ["list","of","strings"]
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err == nil {
		*s = many
		return nil
	}
	// Could be numbers/bools/etc. Ignore gracefully.
	return nil
}

type policyStmt struct {
	Sid         string                 `json:"Sid"`
	Effect      string                 `json:"Effect"`
	Action      strOrList              `json:"Action"`
	NotAction   strOrList              `json:"NotAction"`
	Resource    strOrList              `json:"Resource"`
	NotResource strOrList              `json:"NotResource"`
	Condition   map[string]interface{} `json:"Condition"`
}

func hasWildcard(vals []string) bool {
	for _, v := range vals {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "*" || v == "*:*" || strings.HasSuffix(v, ":*") {
			return true
		}
	}
	return false
}

func hasStar(vals []string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) == "*" {
			return true
		}
	}
	return false
}

type finding struct {
	File        string
	BlockRef    string // e.g., resource.aws_iam_policy.my_policy
	Range       hcl.Range
	StatementID string // Sid or ordinal
	Rule        string
	Details     string
}

func analyzeJSONPolicy(raw string, file string, blockRef string, rng hcl.Range) []types.Finding {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var doc policyDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		// Try to be nice: many policies come from heredocs with interpolations – mark unknown
		return []types.Finding{
			{
				Scanner:     "terraform",
				Rule:        "parse_error",
				Severity:    "HIGH",
				File:        file,
				Line:        rng.Start.Line,
				Column:      rng.Start.Column,
				BlockRef:    blockRef,
				StatementID: "",
				Details:     fmt.Sprintf("Could not parse JSON policy (possibly dynamic/interpolated): %v", err),
			},
		}
	}
	var out []types.Finding
	for i, st := range doc.Statement {
		if strings.EqualFold(st.Effect, "Allow") {
			if hasWildcard(st.Action) {
				out = append(out, types.Finding{
					Scanner:     "terraform",
					Rule:        "allow_action_wildcard",
					Severity:    "HIGH",
					File:        file,
					Line:        rng.Start.Line,
					Column:      rng.Start.Column,
					BlockRef:    blockRef,
					StatementID: nonEmpty(st.Sid, fmt.Sprintf("#%d", i+1)),
					Details:     fmt.Sprintf(`Effect "Allow" with Action wildcard (%v)`, []string(st.Action)),
				})
			}
			if hasStar(st.Resource) {
				out = append(out, types.Finding{
					Scanner:     "terraform",
					Rule:        "allow_resource_star",
					Severity:    "HIGH",
					File:        file,
					Line:        rng.Start.Line,
					Column:      rng.Start.Column,
					BlockRef:    blockRef,
					StatementID: nonEmpty(st.Sid, fmt.Sprintf("#%d", i+1)),
					Details:     `Effect "Allow" with Resource "*"`,
				})
			}
		}
	}
	return out
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// ---------------------------
// HCL helpers for data blocks
// ---------------------------

func exprToStrings(expr hcl.Expression) (vals []string, ok bool) {
	// We only support static literals and tuples of static literals.
	switch e := expr.(type) {
	case *hclsyntax.TemplateExpr:
		// Only accept if it is a constant template with no interpolations
		if len(e.Parts) == 1 {
			if wrap, isWrap := e.Parts[0].(*hclsyntax.TemplateWrapExpr); isWrap {
				if lv, isLv := wrap.Wrapped.(*hclsyntax.LiteralValueExpr); isLv && lv.Val.Type().IsPrimitiveType() {
					return []string{lv.Val.AsString()}, true
				}
			}
		}

	case *hclsyntax.LiteralValueExpr:
		if e.Val.Type().IsPrimitiveType() {
			return []string{e.Val.AsString()}, true
		}

	case *hclsyntax.TupleConsExpr:
		var out []string
		for _, ex := range e.Exprs {
			switch exVal := ex.(type) {
			case *hclsyntax.LiteralValueExpr:
				if exVal.Val.Type().IsPrimitiveType() {
					out = append(out, exVal.Val.AsString())
				} else {
					return nil, false
				}

			case *hclsyntax.TemplateExpr:
				if len(exVal.Parts) == 1 {
					if wrap, ok := exVal.Parts[0].(*hclsyntax.TemplateWrapExpr); ok {
						if lv, isLv := wrap.Wrapped.(*hclsyntax.LiteralValueExpr); isLv && lv.Val.Type().IsPrimitiveType() {
							out = append(out, lv.Val.AsString())
							continue
						}
					}
				}
				return nil, false

			default:
				return nil, false
			}
		}
		return out, true
	}
	return nil, false
}

func getStatementID(block *hclsyntax.Block) (string, bool) {
	attr, ok := block.Body.Attributes["sid"]
	if !ok {
		return "", false // no sid attribute
	}

	// Try to evaluate to a static string
	if lv, ok := attr.Expr.(*hclsyntax.LiteralValueExpr); ok && lv.Val.Type().IsPrimitiveType() {
		return lv.Val.AsString(), true
	}

	// If it's a wrapped template string
	if te, ok := attr.Expr.(*hclsyntax.TemplateExpr); ok && len(te.Parts) == 1 {
		if wrap, ok := te.Parts[0].(*hclsyntax.TemplateWrapExpr); ok {
			if lv, ok := wrap.Wrapped.(*hclsyntax.LiteralValueExpr); ok {
				return lv.Val.AsString(), true
			}
		}
	}

	return "", false
}

// Analyze aws_iam_policy_document { statement { ... } }
func analyzeIAMPolicyDocumentBlock(b *hclsyntax.Block, file string, blockRef string) []types.Finding {
	var out []types.Finding

	for _, st := range b.Body.Blocks {
		if st.Type != "statement" {
			continue
		}
		var effect string
		if attr, ok := st.Body.Attributes["effect"]; ok {
			if vals, ok2 := exprToStrings(attr.Expr); ok2 && len(vals) > 0 {
				effect = strings.TrimSpace(vals[0])
			}
		}
		var actions, notActions, resources, notResources []string
		if attr, ok := st.Body.Attributes["actions"]; ok {
			if vals, ok2 := exprToStrings(attr.Expr); ok2 {
				actions = vals
			}
		}
		if attr, ok := st.Body.Attributes["not_actions"]; ok {
			if vals, ok2 := exprToStrings(attr.Expr); ok2 {
				notActions = vals
			}
		}
		if attr, ok := st.Body.Attributes["resources"]; ok {
			if vals, ok2 := exprToStrings(attr.Expr); ok2 {
				resources = vals
			}
		}
		if attr, ok := st.Body.Attributes["not_resources"]; ok {
			if vals, ok2 := exprToStrings(attr.Expr); ok2 {
				notResources = vals
			}
		}

		// Unknown/dynamic? surface it
		unknown := false
		if _, ok := st.Body.Attributes["actions"]; ok && len(actions) == 0 {
			unknown = true
		}
		if _, ok := st.Body.Attributes["resources"]; ok && len(resources) == 0 {
			unknown = true
		}
		stId, stIdExists := getStatementID(st)
		if !stIdExists {
			stId = ""
		}
		if strings.EqualFold(effect, "Allow") {
			if hasWildcard(actions) {

				out = append(out, types.Finding{
					Scanner:     "terraform",
					Rule:        "allow_action_wildcard",
					Severity:    "high",
					File:        file,
					Line:        st.DefRange().Start.Line,
					Column:      st.DefRange().Start.Column,
					BlockRef:    blockRef,
					StatementID: stId,
				})
			}
			if hasStar(resources) {
				out = append(out, types.Finding{
					Scanner:     "terraform",
					Rule:        "allow_resource_star",
					Severity:    "high",
					File:        file,
					BlockRef:    blockRef,
					Line:        st.DefRange().Start.Line,
					Column:      st.DefRange().Start.Column,
					StatementID: stId,
					Details:     `Effect "Allow" with Resource "*"`,
				})
			}
		}

		// NotActions/NotResources tend to be risky if used with broad sets; surface unknowns
		if unknown || len(notActions) > 0 || len(notResources) > 0 {

			out = append(out, types.Finding{
				Scanner:     "terraform",
				Severity:    "high",
				File:        file,
				Line:        st.DefRange().Start.Line,
				Column:      st.DefRange().Start.Column,
				BlockRef:    blockRef,
				StatementID: stId,
				Rule:        "needs_manual_review",
				Details:     "Uses dynamic values, not_actions, or not_resources; review for permissiveness.",
			})
		}
	}

	return out
}

// ---------------------------
// Main HCL traversal
// ---------------------------

var resourceTypesWithPolicyJSON = map[string]bool{
	"aws_iam_policy":       true,
	"aws_iam_role_policy":  true,
	"aws_iam_user_policy":  true,
	"aws_iam_group_policy": true,
	"aws_s3_bucket_policy": true,
	// Add more resources with inline policy JSON if needed
}

func tryExtractStaticString(expr hcl.Expression) string {
	// Accept raw JSON from a quoted string or heredoc with no interpolations.
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		if e.Val.Type().IsPrimitiveType() {
			return e.Val.AsString()
		}

	case *hclsyntax.TemplateExpr:
		// Constant template only (no ${} parts)
		if len(e.Parts) == 1 {
			if wrap, ok := e.Parts[0].(*hclsyntax.TemplateWrapExpr); ok {
				if lv, isLv := wrap.Wrapped.(*hclsyntax.LiteralValueExpr); isLv && lv.Val.Type().IsPrimitiveType() {
					return lv.Val.AsString()
				}
			}
		}
	}
	return ""
}
