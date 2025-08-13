package types

type Finding struct {
	Scanner     string `json:"scanner"`  // e.g., "terraform", "github_actions"
	Rule        string `json:"rule"`     // e.g., "allow_action_wildcard"
	Severity    string `json:"severity"` // e.g., "HIGH", "MEDIUM", "LOW"
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column,omitempty"`
	BlockRef    string `json:"block_ref"` // e.g., resource.aws_iam_policy.my_policy
	StatementID string `json:"statement_id"`
	Details     string `json:"details"`
}