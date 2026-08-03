// Copyright 2026 Alex O <info@lifub.com>

#ifndef ZEROTRUST_DRIVE_MACOS_FILE_COORDINATION_H
#define ZEROTRUST_DRIVE_MACOS_FILE_COORDINATION_H

#include <stddef.h>
#include <stdint.h>

enum {
    ZTD_MAC_INTENT_READ = 0,
    ZTD_MAC_INTENT_WRITE = 1,
    ZTD_MAC_INTENT_DELETE = 2,
    ZTD_MAC_INTENT_MOVE = 3,
    ZTD_MAC_INTENT_REPLACE = 4,
};

enum {
    ZTD_MAC_DOWNLOAD_NOT_APPLICABLE = 0,
    ZTD_MAC_DOWNLOAD_CURRENT = 1,
    ZTD_MAC_DOWNLOAD_STALE = 2,
    ZTD_MAC_DOWNLOAD_NOT_DOWNLOADED = 3,
    ZTD_MAC_DOWNLOAD_UNKNOWN = 4,
};

enum {
    ZTD_MAC_ERROR_NONE = 0,
    ZTD_MAC_ERROR_FOUNDATION = 1,
    ZTD_MAC_ERROR_ACCESSOR = 2,
    ZTD_MAC_ERROR_EXCEPTION = 3,
    ZTD_MAC_ERROR_INVALID_INPUT = 4,
    ZTD_MAC_ERROR_TIMEOUT = 5,
};

enum {
    ZTD_MAC_ACCESSOR_OK = 0,
    ZTD_MAC_ACCESSOR_FAILED_NOT_MOVED = 1,
    ZTD_MAC_ACCESSOR_FAILED_AFTER_MOVE = 2,
};

#define ZTD_MAC_ERROR_DOMAIN_CAPACITY 128
#define ZTD_MAC_ERROR_MESSAGE_CAPACITY 1024

typedef struct {
    int32_t kind;
    int64_t code;
    char domain[ZTD_MAC_ERROR_DOMAIN_CAPACITY];
    char message[ZTD_MAC_ERROR_MESSAGE_CAPACITY];
} ztd_mac_error;

typedef struct {
    int32_t is_ubiquitous;
    int32_t download_status;
    int32_t download_requested;
    int32_t is_downloading;
    int32_t is_uploaded;
    int32_t is_uploading;
    int32_t has_unresolved_conflicts;
    char download_error[ZTD_MAC_ERROR_MESSAGE_CAPACITY];
    char upload_error[ZTD_MAC_ERROR_MESSAGE_CAPACITY];
} ztd_mac_ubiquity_status;

typedef struct {
    int32_t relinquish_writer_count;
    int32_t move_count;
    int32_t destination_matches;
} ztd_mac_presenter_probe_result;

typedef int32_t (*ztd_mac_accessor)(
    void *context,
    const uint8_t *first_path,
    size_t first_path_len,
    const uint8_t *second_path,
    size_t second_path_len);

int32_t ztd_mac_coordinate_one(
    const uint8_t *purpose,
    size_t purpose_len,
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    int32_t intent,
    ztd_mac_accessor accessor,
    void *context,
    ztd_mac_error *error);

// The synchronous Foundation API has direct read-plus-write and two-write
// variants. Two-read access requires the asynchronous/queue API and is
// intentionally rejected so a non-Send Rust accessor never crosses threads.
int32_t ztd_mac_coordinate_two(
    const uint8_t *purpose,
    size_t purpose_len,
    const uint8_t *first_path,
    size_t first_path_len,
    int32_t first_is_directory,
    int32_t first_intent,
    const uint8_t *second_path,
    size_t second_path_len,
    int32_t second_is_directory,
    int32_t second_intent,
    ztd_mac_accessor accessor,
    void *context,
    ztd_mac_error *error);

// Coordinates exactly one source move and one destination replacement. The
// accessor status reports whether renameat crossed the namespace boundary so
// presenter notification remains correct when a later fsync/checkpoint fails.
int32_t ztd_mac_coordinate_move(
    const uint8_t *purpose,
    size_t purpose_len,
    const uint8_t *source_path,
    size_t source_path_len,
    int32_t source_is_directory,
    const uint8_t *destination_path,
    size_t destination_path_len,
    int32_t destination_is_directory,
    ztd_mac_accessor accessor,
    void *context,
    ztd_mac_error *error);

int32_t ztd_mac_query_ubiquity(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_ubiquity_status *status,
    ztd_mac_error *error);

int32_t ztd_mac_start_download(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_error *error);

// Test-only callers use this to prove a real dataless-to-materialized iCloud
// transition. FileManager eviction removes only the local copy; it does not
// delete the remote item.
int32_t ztd_mac_evict_ubiquitous_item(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_error *error);

// Test probe for the exact move shim. It registers an independent
// NSFilePresenter for source_path, performs the existing coordinated move, and
// waits at most timeout_millis for the move notification. The accessor remains
// synchronous and caller-owned exactly as in ztd_mac_coordinate_move.
int32_t ztd_mac_probe_coordinated_move(
    const uint8_t *purpose,
    size_t purpose_len,
    const uint8_t *source_path,
    size_t source_path_len,
    int32_t source_is_directory,
    const uint8_t *destination_path,
    size_t destination_path_len,
    int32_t destination_is_directory,
    uint64_t timeout_millis,
    ztd_mac_accessor accessor,
    void *context,
    ztd_mac_presenter_probe_result *result,
    ztd_mac_error *error);

#endif
