package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// ensureResourceGroup converges the target resource group: create it, tagged
// as ours, when it does not exist; adopt it unmodified when it does.
//
// An adopted group's tags are left exactly as found. Delete never removes the
// resource group (it may hold other installations' identities), so tagging
// one we did not create would claim an ownership we can never act on, and a
// group whose location does not match the request cannot be converged at
// all: location is immutable on an Azure resource group.
func (az *Azure) ensureResourceGroup(ctx context.Context) error {
	existing, err := az.resourceGroups.Get(ctx, az.resourceGroup, nil)
	if err == nil {
		if got := deref(existing.Location); got != az.location {
			return &LocationMismatchError{ResourceGroup: az.resourceGroup, Existing: got, Requested: az.location}
		}
		return nil
	}
	if armStatusCode(err) != 404 {
		return err
	}

	_, err = az.resourceGroups.CreateOrUpdate(ctx, az.resourceGroup, armresources.ResourceGroup{
		Location: to.Ptr(az.location),
		Tags:     map[string]*string{ownerTagKey: to.Ptr(ownerTagValue)},
	}, nil)
	return err
}
