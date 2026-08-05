// Copyright 2026 Alex O <info@lifub.com>
//
// Bridging header for macos_file_coordination.swift. It exposes exactly the
// C ABI contract (macos_file_coordination.h) that Rust declares against, plus
// the Objective-C exception guard the Swift shim must route Foundation work
// through. Keep this header free of any other declarations so the .h files
// remain the single source of truth for the boundary.

#include "macos_file_coordination.h"
#include "macos_exception_guard.h"
