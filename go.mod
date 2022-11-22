module estrace

go 1.18

require (
	github.com/cilium/ebpf v0.9.3
	github.com/ehids/ebpfmanager v0.3.0
	github.com/shuLhan/go-bindata v4.0.0+incompatible
	github.com/spf13/cobra v1.6.1
	golang.org/x/sys v0.2.0
)

replace github.com/cilium/ebpf => ../ebpf

replace github.com/ehids/ebpfmanager => ../ebpfmanager

require (
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/florianl/go-tc v0.4.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/mdlayher/netlink v1.7.0 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.1 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
)

require (
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)
