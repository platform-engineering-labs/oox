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
