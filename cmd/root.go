package cmd

import (
	"github.com/kubewarden/audit-scanner/internal/client"
	"github.com/kubewarden/audit-scanner/internal/scanner"
	"github.com/spf13/cobra"
	"os"
)

// rootCmd represents the base command when called without any subcommands
var (
	rootCmd = &cobra.Command{
		Use:   "audit-scanner",
		Short: "Reports evaluation of existing Kubernetes resources with your already deployed Kubewarden policies",
		Long: `Scans resources in your kubernetes cluster with your already deployed Kubewarden policies.
Each namespace will have a PolicyReport with the outcome of the scan for resources within this namespace.
There will be a ClusterPolicyReport with results for cluster-wide resources.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			namespace, err := cmd.Flags().GetString("namespace")
			if err != nil {
				return err
			}
			client, err := client.NewClient()
			if err != nil {
				return err
			}
			scanner := scanner.NewScanner(client)

			return startScanner(namespace, scanner)
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func startScanner(namespace string, scanner scanner.Scanner) error {
	if namespace != "" {
		if err := scanner.ScanNamespace(namespace); err != nil {
			return err
		}
	} else {
		if err := scanner.ScanAllNamespaces(); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	rootCmd.Flags().StringP("namespace", "n", "", "namespace to be evaluated")
}
