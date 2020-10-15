module github.com/niclabs/dnszeppelin

go 1.15

require (
	github.com/davecgh/go-spew v1.1.0 // indirect
	github.com/google/gopacket v1.1.18
	github.com/miekg/dns v1.1.33
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.1.4
)

replace github.com/miekg/dns v1.1.33 => github.com/niclabs/dns v1.1.33
