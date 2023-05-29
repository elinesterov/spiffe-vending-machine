package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

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
	Debug            bool
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

		if Debug {
			Log, err = zap.NewProduction()
		} else {
			Log, err = zap.NewDevelopment()
		}

		if err != nil {
			return err
		}

		socketDir := filepath.Dir(SpiffeSocketPath)
		if _, err := os.Stat(socketDir); os.IsNotExist(err) {
			err = os.MkdirAll(socketDir, 0755)
			if err != nil {
				return fmt.Errorf("failed to create SPIFFE Socket Path directory: %s, error: %v", socketDir, err)
			}
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
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "Enable debug logging")
}
