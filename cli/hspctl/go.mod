module github.com/loxar/hsp/cli/hspctl

go 1.25.0

toolchain go1.25.11

require github.com/loxar/hsp/sdk/go v0.0.0

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

replace github.com/loxar/hsp/sdk/go => ../../sdk/go
