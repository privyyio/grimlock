package utils

import (
	"runtime"
)

// SecureErase attempts to securely erase sensitive data from memory
// Note: Go's garbage collector makes true secure erasure difficult,
// but we can at least zero the memory we control
func SecureErase(data []byte) {
	if data == nil {
		return
	}
	
	// Zero out the memory
	for i := range data {
		data[i] = 0
	}
	
	// Force garbage collection to clean up
	// Note: This is a hint, not a guarantee
	runtime.GC()
}

// SecureEraseString attempts to erase a string (limited effectiveness in Go)
// Note: Strings in Go are immutable, so this has limited effectiveness
// It's better to use []byte for sensitive data
func SecureEraseString(s *string) {
	if s != nil {
		*s = ""
	}
}

// SecureEraseMultiple erases multiple byte slices
func SecureEraseMultiple(data ...[]byte) {
	for _, d := range data {
		SecureErase(d)
	}
}

// CopyAndErase copies data to a new slice and erases the original
func CopyAndErase(data []byte) []byte {
	if data == nil {
		return nil
	}
	
	copied := make([]byte, len(data))
	copy(copied, data)
	SecureErase(data)
	
	return copied
}
