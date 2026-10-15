module github.com/Voxmatic/observe

// Language level 1.24 so the code builds with the Go 1.24.7 toolchain in the
// development workspace, where the module proxy is not reachable. CI and
// Astra build and test with Go 1.27 (technology row T1). See
// docs/adr/0002-technology-choices.md.
go 1.24.0
