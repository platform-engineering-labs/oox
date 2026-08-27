package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/platform-engineering-labs/oox/provx"
	"github.com/platform-engineering-labs/oox/provx/gcp"
	"github.com/spf13/cobra"
)

func init() {
	ProvisionGCP.AddCommand(ProvisionGCPCreate)
	ProvisionGCP.AddCommand(ProvisionGCPDelete)

	ProvisionGCPCreate.Flags().String("project", "", "GCP Project")

	ProvisionGCPDelete.Flags().String("project", "", "GCP Project")
}

var ProvisionGCP = &cobra.Command{
	Use:   "gcp",
	Short: "provision an oidc connector to GCP",
}

var ProvisionGCPCreate = &cobra.Command{
	Use:   "create [tenantId] [installationId]",
	Short: "provision oidc connector to GCP",

	RunE: func(cmd *cobra.Command, args []string) error {
		project, _ := cmd.Flags().GetString("project")

		if project == "" {
			return fmt.Errorf("must provide project")
		}

		tenantId := cmd.Flags().Arg(0)
		if tenantId == "" {
			return fmt.Errorf("must provide tenant id")
		}

		installationId := cmd.Flags().Arg(1)
		if installationId == "" {
			return fmt.Errorf("must provide installation id")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		prov, err := gcp.New(ctx, slog.New(Logger), project, tenantId, installationId, "https://"+provx.Endpoint)
		if err != nil {
			return err
		}

		res, err := prov.Create(ctx)
		if err != nil {
			return err
		}

		fmt.Println(res.ProviderName)
		return nil
	},
}

var ProvisionGCPDelete = &cobra.Command{
	Use:   "delete [tenantId] [installationId]",
	Short: "de-provision oidc connector from GCP",

	RunE: func(cmd *cobra.Command, args []string) error {
		project, _ := cmd.Flags().GetString("project")

		if project == "" {
			return fmt.Errorf("must provide project")
		}

		tenantId := cmd.Flags().Arg(0)
		if tenantId == "" {
			return fmt.Errorf("must provide tenant id")
		}

		installationId := cmd.Flags().Arg(1)
		if installationId == "" {
			return fmt.Errorf("must provide installation id")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		prov, err := gcp.New(ctx, slog.New(Logger), project, tenantId, installationId, "https://"+provx.Endpoint)
		if err != nil {
			return err
		}

		err = prov.Delete(ctx)
		if err != nil {
			return err
		}

		return nil
	},
}
