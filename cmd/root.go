package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "svmctl",
	Short: "SPIFFE Vending Machine CLI",
	Long:  `SPIFFE Vending Machine CLI is a tool for managing SPIFFE Vending Machine.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do some stuff here
		cmd.Print("SPIFFE Vending Machine CLI")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
