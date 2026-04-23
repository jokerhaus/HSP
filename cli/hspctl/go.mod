module github.com/loxar/hsp/cli/hspctl

go 1.25.0

toolchain go1.25.9

require github.com/loxar/hsp/sdk/go v0.0.0

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)

replace github.com/loxar/hsp/sdk/go => ../../sdk/go
