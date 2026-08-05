// Copyright 2026 Alex O <info@lifub.com>

#ifndef ZEROTRUST_DRIVE_MACOS_EXCEPTION_GUARD_H
#define ZEROTRUST_DRIVE_MACOS_EXCEPTION_GUARD_H

#include "macos_file_coordination.h"

// Runs `body` under an Objective-C @try/@catch and converts a raised
// NSException into the structured ZTD_MAC_ERROR_EXCEPTION contract. This is
// the one capability the Swift shim cannot provide itself: Swift has no
// NSException catch construct, and an NSException unwinding across the Rust
// `extern "C"` boundary is undefined behavior. On exception the guard fills
// `error` (kind, name as domain, reason as message) and returns -1; otherwise
// it returns `body`'s result and leaves `error` untouched.
int32_t ztd_mac_exception_guard(int32_t (^body)(void), ztd_mac_error *error);

// Test-only, following the ztd_mac_evict_ubiquitous_item precedent of shipping
// narrowly documented test entry points. Raises a synthetic NSException so a
// Rust regression test can prove that an exception raised beneath Swift frames
// is contained by the guard instead of aborting the process.
void ztd_mac_test_raise_foundation_exception(void);

#endif
