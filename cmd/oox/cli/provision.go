package cli

import (
	"github.com/spf13/cobra"
)

func init() {
	Provision.AddCommand(ProvisionAWS)
	Provision.AddCommand(ProvisionGCP)
}

var Provision = &cobra.Command{
	Use:   "provision",
	Short: "provision oidc connectors",
}
