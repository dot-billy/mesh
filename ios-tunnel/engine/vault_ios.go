//go:build ios

package iosmobile

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef mesh_string(const char *value) {
	return CFStringCreateWithCString(
		kCFAllocatorDefault,
		value,
		kCFStringEncodingUTF8
	);
}

static void mesh_base_query(
	CFMutableDictionaryRef query,
	CFStringRef access_group,
	CFStringRef service,
	CFStringRef account
) {
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrAccessGroup, access_group);
	CFDictionarySetValue(query, kSecAttrService, service);
	CFDictionarySetValue(query, kSecAttrAccount, account);
	CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
	CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
}

static OSStatus mesh_copy_key(
	CFStringRef access_group,
	CFStringRef service,
	CFStringRef account,
	uint8_t output[32]
) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (query == NULL) {
		return errSecAllocate;
	}
	mesh_base_query(query, access_group, service, account);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) {
		if (result != NULL) {
			CFRelease(result);
		}
		return status;
	}
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) {
			CFRelease(result);
		}
		return errSecDecode;
	}
	CFDataRef data = (CFDataRef)result;
	if (CFDataGetLength(data) != 32) {
		CFRelease(result);
		return errSecDecode;
	}
	CFDataGetBytes(data, CFRangeMake(0, 32), output);
	CFRelease(result);
	return errSecSuccess;
}

static OSStatus mesh_load_or_create_key(
	const char *raw_access_group,
	const char *raw_service,
	const char *raw_account,
	uint8_t output[32]
) {
	CFStringRef access_group = mesh_string(raw_access_group);
	CFStringRef service = mesh_string(raw_service);
	CFStringRef account = mesh_string(raw_account);
	if (access_group == NULL || service == NULL || account == NULL) {
		if (access_group != NULL) CFRelease(access_group);
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		return errSecParam;
	}

	OSStatus status = mesh_copy_key(access_group, service, account, output);
	if (status == errSecItemNotFound) {
		status = SecRandomCopyBytes(kSecRandomDefault, 32, output);
		if (status == errSecSuccess) {
			CFDataRef data = CFDataCreate(kCFAllocatorDefault, output, 32);
			CFMutableDictionaryRef add = CFDictionaryCreateMutable(
				kCFAllocatorDefault,
				0,
				&kCFTypeDictionaryKeyCallBacks,
				&kCFTypeDictionaryValueCallBacks
			);
			if (data == NULL || add == NULL) {
				if (data != NULL) CFRelease(data);
				if (add != NULL) CFRelease(add);
				memset(output, 0, 32);
				status = errSecAllocate;
			} else {
				mesh_base_query(add, access_group, service, account);
				CFDictionarySetValue(
					add,
					kSecAttrAccessible,
					kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
				);
				CFDictionarySetValue(add, kSecValueData, data);
				status = SecItemAdd(add, NULL);
				CFRelease(data);
				CFRelease(add);
				if (status == errSecDuplicateItem) {
					memset(output, 0, 32);
					status = mesh_copy_key(
						access_group,
						service,
						account,
						output
					);
				}
			}
		}
	}
	CFRelease(access_group);
	CFRelease(service);
	CFRelease(account);
	return status;
}

static OSStatus mesh_load_key(
	const char *raw_access_group,
	const char *raw_service,
	const char *raw_account,
	uint8_t output[32]
) {
	CFStringRef access_group = mesh_string(raw_access_group);
	CFStringRef service = mesh_string(raw_service);
	CFStringRef account = mesh_string(raw_account);
	if (access_group == NULL || service == NULL || account == NULL) {
		if (access_group != NULL) CFRelease(access_group);
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		return errSecParam;
	}
	OSStatus status = mesh_copy_key(
		access_group,
		service,
		account,
		output
	);
	CFRelease(access_group);
	CFRelease(service);
	CFRelease(account);
	return status;
}

static OSStatus mesh_replace_key(
	const char *raw_access_group,
	const char *raw_service,
	const char *raw_account,
	const uint8_t input[32]
) {
	CFStringRef access_group = mesh_string(raw_access_group);
	CFStringRef service = mesh_string(raw_service);
	CFStringRef account = mesh_string(raw_account);
	if (access_group == NULL || service == NULL || account == NULL) {
		if (access_group != NULL) CFRelease(access_group);
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		return errSecParam;
	}
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFMutableDictionaryRef update = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, input, 32);
	OSStatus status = errSecAllocate;
	if (query != NULL && update != NULL && data != NULL) {
		mesh_base_query(query, access_group, service, account);
		CFDictionarySetValue(update, kSecValueData, data);
		CFDictionarySetValue(
			update,
			kSecAttrAccessible,
			kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		);
		status = SecItemUpdate(query, update);
	}
	if (data != NULL) CFRelease(data);
	if (update != NULL) CFRelease(update);
	if (query != NULL) CFRelease(query);
	CFRelease(access_group);
	CFRelease(service);
	CFRelease(account);
	return status;
}

static OSStatus mesh_delete_key(
	const char *raw_access_group,
	const char *raw_service,
	const char *raw_account
) {
	CFStringRef access_group = mesh_string(raw_access_group);
	CFStringRef service = mesh_string(raw_service);
	CFStringRef account = mesh_string(raw_account);
	if (access_group == NULL || service == NULL || account == NULL) {
		if (access_group != NULL) CFRelease(access_group);
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		return errSecParam;
	}
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	OSStatus status = errSecAllocate;
	if (query != NULL) {
		mesh_base_query(query, access_group, service, account);
		status = SecItemDelete(query);
		CFRelease(query);
	}
	CFRelease(access_group);
	CFRelease(service);
	CFRelease(account);
	return status;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func loadOrCreatePrivateKey(accessGroup, identityID string) ([]byte, error) {
	return loadOrCreateSecret(accessGroup, identityService, identityID)
}

func loadPrivateKey(accessGroup, identityID string) ([]byte, error) {
	return loadSecret(accessGroup, identityService, identityID)
}

func loadOrCreateSecret(
	accessGroup string,
	serviceValue string,
	accountValue string,
) ([]byte, error) {
	group := C.CString(accessGroup)
	service := C.CString(serviceValue)
	account := C.CString(accountValue)
	defer C.free(unsafe.Pointer(group))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))

	privateKey := make([]byte, 32)
	status := C.mesh_load_or_create_key(
		group,
		service,
		account,
		(*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
	)
	if status != C.errSecSuccess {
		clear(privateKey)
		return nil, errors.New("Keychain operation was rejected")
	}
	return privateKey, nil
}

func loadSecret(
	accessGroup string,
	serviceValue string,
	accountValue string,
) ([]byte, error) {
	group := C.CString(accessGroup)
	service := C.CString(serviceValue)
	account := C.CString(accountValue)
	defer C.free(unsafe.Pointer(group))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))

	secret := make([]byte, 32)
	status := C.mesh_load_key(
		group,
		service,
		account,
		(*C.uint8_t)(unsafe.Pointer(&secret[0])),
	)
	if status != C.errSecSuccess {
		clear(secret)
		return nil, errors.New("Keychain item is unavailable")
	}
	return secret, nil
}

func replaceSecret(
	accessGroup string,
	serviceValue string,
	accountValue string,
	secret []byte,
) error {
	if len(secret) != 32 {
		return errors.New("Keychain replacement value is invalid")
	}
	group := C.CString(accessGroup)
	service := C.CString(serviceValue)
	account := C.CString(accountValue)
	defer C.free(unsafe.Pointer(group))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))

	status := C.mesh_replace_key(
		group,
		service,
		account,
		(*C.uint8_t)(unsafe.Pointer(&secret[0])),
	)
	if status != C.errSecSuccess {
		return errors.New("Keychain replacement was rejected")
	}
	return nil
}

func deleteSecret(
	accessGroup string,
	serviceValue string,
	accountValue string,
) error {
	group := C.CString(accessGroup)
	service := C.CString(serviceValue)
	account := C.CString(accountValue)
	defer C.free(unsafe.Pointer(group))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))

	status := C.mesh_delete_key(group, service, account)
	if status != C.errSecSuccess && status != C.errSecItemNotFound {
		return errors.New("Keychain deletion was rejected")
	}
	return nil
}
