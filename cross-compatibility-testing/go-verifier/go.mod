module github.com/privyy-io/grimlock/cross-compatibility-testing/go-verifier

go 1.24.0

replace github.com/privyy-io/grimlock/go/grimlock => ../../go/grimlock

require github.com/privyy-io/grimlock/go/grimlock v0.0.0-00010101000000-000000000000

require (
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)
