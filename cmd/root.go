package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var folder string

var rootCmd = &cobra.Command{
	Use:   "scanizard",
	Short: "Scanizard is a SAST tool for IaC and CI/CD configuration files",
	Long:  `Scanizard performs static analysis on Terraform, GitHub Actions, GitLab CI, and Ansible configurations.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&folder, "folder", "f", ".", "Folder containing the relevant files")
}
