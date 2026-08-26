//go:build darwin

package store

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

// The SecTrustedApplication / SecAccess / SecKeychainItemSetAccess APIs are
// deprecated since macOS 10.10, but remain the ONLY way to set per-application
// trust lists on keychain items. The modern SecAccessControl API handles user
// authentication (biometric, passcode) but has no concept of app-level ACLs.
// Apple has not removed these APIs or provided a replacement.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// applyACLToItem finds a keychain item by service+account and restricts
// access to the calling binary. Other applications will trigger a Keychain
// Access prompt instead of reading the secret silently.
static OSStatus applyACLToItem(const char *service, const char *account) {
	OSStatus status;

	CFStringRef cfService = CFStringCreateWithCString(
		NULL, service, kCFStringEncodingUTF8);
	CFStringRef cfAccount = CFStringCreateWithCString(
		NULL, account, kCFStringEncodingUTF8);

	// Query for the item reference.
	const void *qKeys[] = {
		kSecClass, kSecAttrService, kSecAttrAccount,
		kSecMatchLimit, kSecReturnRef,
	};
	const void *qVals[] = {
		kSecClassGenericPassword, cfService, cfAccount,
		kSecMatchLimitOne, kCFBooleanTrue,
	};
	CFDictionaryRef query = CFDictionaryCreate(
		NULL, qKeys, qVals, 5,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);

	CFTypeRef itemRef = NULL;
	status = SecItemCopyMatching(query, &itemRef);
	CFRelease(query);
	CFRelease(cfService);
	CFRelease(cfAccount);
	if (status != errSecSuccess || itemRef == NULL) {
		return status;
	}

	// Create a trusted-application entry for the calling binary (NULL = self).
	SecTrustedApplicationRef self = NULL;
	status = SecTrustedApplicationCreateFromPath(NULL, &self);
	if (status != errSecSuccess) {
		CFRelease(itemRef);
		return status;
	}

	// Build a SecAccessRef where only this binary is trusted.
	CFArrayRef apps = CFArrayCreate(
		NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
	SecAccessRef access = NULL;
	status = SecAccessCreate(CFSTR("scredmgr"), apps, &access);
	CFRelease(apps);
	CFRelease(self);
	if (status != errSecSuccess) {
		CFRelease(itemRef);
		return status;
	}

	// Apply the access restriction to the existing item.
	status = SecKeychainItemSetAccess((SecKeychainItemRef)itemRef, access);
	CFRelease(access);
	CFRelease(itemRef);
	return status;
}

#pragma clang diagnostic pop
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// applyACL restricts the keychain item for id so that only the current
// executable can read it without a user prompt. Other applications will
// trigger a Keychain Access dialog. Failures are logged to stderr but
// do not block the caller — ACL enforcement is best-effort.
func applyACL(id string) {
	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(accountPrefix + id)
	defer C.free(unsafe.Pointer(cAccount))

	status := C.applyACLToItem(cService, cAccount)
	if status != 0 {
		fmt.Fprintf(os.Stderr, "scredmgr: set keychain ACL for %s: OSStatus %d\n", id, int(status))
	}
}
