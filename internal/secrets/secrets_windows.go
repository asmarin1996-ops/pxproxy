//go:build windows

package secrets

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const supported = true

var errEmptyInput = errors.New("secrets: entrada vacia")

func blobBytes(out *windows.DataBlob) []byte {
	if out.Data == nil || out.Size == 0 {
		return nil
	}
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return res
}

func dpapiSeal(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errEmptyInput
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return blobBytes(&out), nil
}

func dpapiOpen(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errEmptyInput
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return blobBytes(&out), nil
}
