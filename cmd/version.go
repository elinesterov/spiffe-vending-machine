package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of svmctl",
	Long:  `Print the version number of SPIFFE Vending Machine CLI`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Update to a proper mechanism of verisoning
		fmt.Println("v.0.0.1")
	},
}
