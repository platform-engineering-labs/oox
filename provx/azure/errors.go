package azure

import "fmt"

// LocationMismatchError: a resource group of the requested name already
// exists in a different location. A resource group's location is immutable,
// so there is no way to converge it: renaming the request or moving the
// group are both outside what this package will do on its own.
type LocationMismatchError struct {
	ResourceGroup, Existing, Requested string
}

func (e *LocationMismatchError) Error() string {
	return fmt.Sprintf("resource group %s exists in %s, not the requested %s; a resource group's location cannot be changed",
		e.ResourceGroup, e.Existing, e.Requested)
}

// IdentityNotOursError: the managed identity carries a federated credential
// this package does not recognize as its own - either a second credential
// alongside a matching one, or a single credential whose issuer, subject or
// audience differ. Either way the identity is not safely ours to use: a
// federated credential grants near-owner access to whoever can present a
// matching token, so adopting it on a name match alone would hand that
// access to something we did not create and cannot account for.
type IdentityNotOursError struct {
	Name, Reason string
}

func (e *IdentityNotOursError) Error() string {
	return fmt.Sprintf("managed identity carries a federated credential %q we do not recognize (%s); remove it before formae can adopt this identity",
		e.Name, e.Reason)
}
