// Copyright 2026 Alex O <info@lifub.com>
//
// The complete Foundation-facing shim logic lives in
// macos_file_coordination.swift. This file must stay minimal and must remain
// Objective-C: Swift cannot catch NSExceptions, and Foundation's coordination,
// URL, and presenter APIs signal misuse by raising them. An exception that
// unwinds across the Rust `extern "C"` boundary is undefined behavior, and an
// uncaught one beneath Swift frames terminates the process - the exact
// mid-commit abort the root-last publication protocol exists to eliminate.
// Every exported Swift entry point therefore routes its Foundation work
// through ztd_mac_exception_guard. Do not add Foundation logic here, and do
// not remove the guard.
//
// Parity note: cleanups in Swift frames between the raise and this catch are
// skipped (a bounded leak on the exceptional path). The previous all-ObjC shim
// had the identical property because ARC is not exception-safe without
// -fobjc-arc-exceptions.

#import <Foundation/Foundation.h>

#include "macos_exception_guard.h"

#include <string.h>

static void ztd_guard_copy_string(char *destination, size_t capacity, NSString *value) {
    if (destination == NULL || capacity == 0) {
        return;
    }
    destination[0] = '\0';
    if (value == nil) {
        return;
    }
    const char *utf8 = value.UTF8String;
    if (utf8 == NULL) {
        return;
    }
    size_t length = strlen(utf8);
    if (length >= capacity) {
        length = capacity - 1;
    }
    memcpy(destination, utf8, length);
    destination[length] = '\0';
}

int32_t ztd_mac_exception_guard(int32_t (^body)(void), ztd_mac_error *error) {
    if (body == NULL) {
        if (error != NULL) {
            memset(error, 0, sizeof(*error));
            error->kind = ZTD_MAC_ERROR_INVALID_INPUT;
            ztd_guard_copy_string(error->domain, sizeof(error->domain), @"zerotrust-drive");
            ztd_guard_copy_string(
                error->message,
                sizeof(error->message),
                @"the exception guard requires a body");
        }
        return -1;
    }
    @try {
        return body();
    } @catch (NSException *exception) {
        if (error != NULL) {
            memset(error, 0, sizeof(*error));
            error->kind = ZTD_MAC_ERROR_EXCEPTION;
            ztd_guard_copy_string(error->domain, sizeof(error->domain), exception.name);
            ztd_guard_copy_string(error->message, sizeof(error->message), exception.reason);
        }
        return -1;
    }
}

void ztd_mac_test_raise_foundation_exception(void) {
    [NSException raise:@"ZTDSyntheticTestException"
                format:@"synthetic Foundation exception for containment tests"];
}
