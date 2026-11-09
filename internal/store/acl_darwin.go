//go:build darwin

package store

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

// The SecTrustedApplication / SecAccess APIs are deprecated since macOS 10.10,
// but remain the ONLY way to set per-application trust lists on keychain
// items. The modern SecAccessControl API handles user authentication
// (biometric, passcode) but has no concept of app-level ACLs. Apple has not
// removed these APIs or provided a replacement.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// addItemWithACL creates a generic-password item whose access list trusts only
// the calling binary, in one SecItemAdd. The access list goes in at creation
// (kSecAttrAccess) rather than being applied afterwards: changing an existing
// item's access list is a "wants to change access permissions" password
// prompt, which made every new entry cost several prompts (2026-11-09).
static OSStatus addItemWithACL(const char *service, const char *account,
                               const char *label, const void *data, long len) {
	SecTrustedApplicationRef self = NULL;
	OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &self);
	if (status != errSecSuccess) {
		return status;
	}
	CFArrayRef apps = CFArrayCreate(
		NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
	SecAccessRef access = NULL;
	status = SecAccessCreate(CFSTR("scredmgr"), apps, &access);
	CFRelease(apps);
	CFRelease(self);
	if (status != errSecSuccess) {
		return status;
	}

	CFStringRef cfService = CFStringCreateWithCString(
		NULL, service, kCFStringEncodingUTF8);
	CFStringRef cfAccount = CFStringCreateWithCString(
		NULL, account, kCFStringEncodingUTF8);
	CFStringRef cfLabel = CFStringCreateWithCString(
		NULL, label, kCFStringEncodingUTF8);
	CFDataRef cfData = CFDataCreate(NULL, (const UInt8 *)data, len);

	const void *keys[] = {
		kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrLabel,
		kSecValueData, kSecAttrAccess,
	};
	const void *vals[] = {
		kSecClassGenericPassword, cfService, cfAccount, cfLabel,
		cfData, access,
	};
	CFDictionaryRef attrs = CFDictionaryCreate(
		NULL, keys, vals, 6,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);

	status = SecItemAdd(attrs, NULL);

	CFRelease(attrs);
	CFRelease(cfData);
	CFRelease(cfLabel);
	CFRelease(cfAccount);
	CFRelease(cfService);
	CFRelease(access);
	return status;
}

#pragma clang diagnostic pop
*/
import "C"

import (
	"unsafe"

	keychain "github.com/keybase/go-keychain"
)

// addWithACL stores a new keychain item for id that only the current
// executable can read without a prompt; other applications get a Keychain
// Access dialog. It returns keychain.ErrorDuplicateItem if the item exists.
func addWithACL(id string, secret []byte) error {
	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(accountPrefix + id)
	defer C.free(unsafe.Pointer(cAccount))
	cLabel := C.CString("scredmgr: " + id)
	defer C.free(unsafe.Pointer(cLabel))

	var p unsafe.Pointer
	if len(secret) > 0 {
		p = C.CBytes(secret)
		defer C.free(p)
	}
	status := C.addItemWithACL(cService, cAccount, cLabel, p, C.long(len(secret)))
	if status != 0 {
		return keychain.Error(status)
	}
	return nil
}
