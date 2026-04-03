package v1

import "github.com/privyyio/grimlock/go/grimlock/utils"

// SecureErase securely erases sensitive data from memory
func SecureErase(data []byte) {
	utils.SecureErase(data)
}

// SecureEraseMultiple erases multiple byte slices
func SecureEraseMultiple(data ...[]byte) {
	utils.SecureEraseMultiple(data...)
}
