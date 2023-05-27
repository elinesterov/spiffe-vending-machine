package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/elinesterov/spiffe-vending-machine/pkg/agent"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	// DefaultSocketPath is the default path for the SPIFFE Workload API socket.
	DefaultSocketPath = "/tmp/agent.sock"
)

var (
	c                agent.Config
	Log              *zap.Logger
	SpiffeSocketPath string
)

var rootCmd = &cobra.Command{
	Use:   "svmctl",
	Short: "SPIFFE Vending Machine CLI",
	Long:  `SPIFFE Vending Machine CLI is a tool for managing SPIFFE Vending Machine.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Do some stuff here
		cmd.Print("SPIFFE Vending Machine CLI")
		c.Log = Log
		c.BindAddress = &net.UnixAddr{
			Name: SpiffeSocketPath,
			Net:  "unix",
		}

		a := agent.New(&c)
		if err := a.Run(cmd.Context()); err != nil {
			Log.Error("Failed to run agent", zap.Error(err))
			return err
		}

		return nil
	},

	// Initialize Logger and check SpiifeSocketPath
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		Log, err = zap.NewProduction()
		if err != nil {
			return err
		}

		if SpiffeSocketPath == "" {
			return fmt.Errorf("SPIFFE Socket Path is required")
		}

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&SpiffeSocketPath, "spiffe-socket-path", "s", DefaultSocketPath, "SPIFFE Socket Path")
}
