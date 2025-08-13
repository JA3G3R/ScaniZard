package cmd

import (
	"fmt"

	"github.com/JA3G3R/scanizard/scanners"
	"github.com/spf13/cobra"
)

var terraformCmd = &cobra.Command{
	Use:   "terraform",
	Short: "Scan Terraform files",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Scanning Terraform files in:", folder)
		scanners.ScanTerraform(folder)
	},
}

func init() {
	rootCmd.AddCommand(terraformCmd)
}
