package cmd

import (
	"github.com/elinesterov/spiffe-vending-machine/pkg/common/version"
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
		v := version.Version()
		cmd.Printf("SPIFFE Vending Machine CLI %s\n", v)
	},
}
