// gcpname is its own module, and deliberately requires nothing.
//
// Its consumers are a provisioner, a resource plugin, a credential broker and
// a CLI, in three repositories. Living in the root oox module would force all
// of them to that module's Go floor and drag its cloud SDKs into their build
// graphs, for a package that is string handling and stdlib only. The formae
// CLI in particular pins an older Go than oox root requires, so the root
// module is not available to it at all.
module github.com/platform-engineering-labs/oox/gcpname

go 1.26.0
