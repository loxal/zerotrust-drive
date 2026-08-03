// Copyright 2026 Alex O <info@lifub.com>

#import <Foundation/Foundation.h>

#include "macos_file_coordination.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void ztd_clear_error(ztd_mac_error *error) {
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
    }
}

static void ztd_copy_string(char *destination, size_t capacity, NSString *value) {
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

static void ztd_set_error(
    ztd_mac_error *error,
    int32_t kind,
    int64_t code,
    NSString *domain,
    NSString *message) {
    if (error == NULL) {
        return;
    }
    memset(error, 0, sizeof(*error));
    error->kind = kind;
    error->code = code;
    ztd_copy_string(error->domain, sizeof(error->domain), domain);
    ztd_copy_string(error->message, sizeof(error->message), message);
}

static void ztd_set_foundation_error(ztd_mac_error *error, NSError *foundation_error) {
    ztd_set_error(
        error,
        ZTD_MAC_ERROR_FOUNDATION,
        foundation_error.code,
        foundation_error.domain,
        foundation_error.localizedDescription);
}

static NSURL *ztd_file_url(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_error *error) {
    if (path == NULL || path_len == 0 || path_len == SIZE_MAX ||
        memchr(path, '\0', path_len) != NULL) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"file coordination requires a nonempty NUL-free filesystem path");
        return nil;
    }
    char *terminated = malloc(path_len + 1);
    if (terminated == NULL) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            ENOMEM,
            NSPOSIXErrorDomain,
            @"cannot allocate a temporary filesystem path");
        return nil;
    }
    memcpy(terminated, path, path_len);
    terminated[path_len] = '\0';
    NSURL *url = [NSURL fileURLWithFileSystemRepresentation:terminated
                                                isDirectory:is_directory != 0
                                              relativeToURL:nil];
    free(terminated);
    if (url == nil) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"Foundation rejected the filesystem path");
    }
    return url;
}

static NSString *ztd_purpose_identifier(
    const uint8_t *purpose,
    size_t purpose_len,
    ztd_mac_error *error) {
    if (purpose == NULL || purpose_len == 0 || memchr(purpose, '\0', purpose_len) != NULL) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"file coordination requires a nonempty NUL-free purpose identifier");
        return nil;
    }
    NSString *identifier = [[NSString alloc] initWithBytes:purpose
                                                    length:purpose_len
                                                  encoding:NSUTF8StringEncoding];
    if (identifier.length == 0) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"file coordination purpose identifier is not valid UTF-8");
        return nil;
    }
    return identifier;
}

static BOOL ztd_is_write_intent(int32_t intent) {
    return intent == ZTD_MAC_INTENT_WRITE || intent == ZTD_MAC_INTENT_DELETE ||
           intent == ZTD_MAC_INTENT_MOVE || intent == ZTD_MAC_INTENT_REPLACE;
}

static BOOL ztd_valid_intent(int32_t intent) {
    return intent == ZTD_MAC_INTENT_READ || ztd_is_write_intent(intent);
}

static NSFileCoordinatorWritingOptions ztd_writing_options(int32_t intent) {
    switch (intent) {
        case ZTD_MAC_INTENT_DELETE:
            return NSFileCoordinatorWritingForDeleting;
        case ZTD_MAC_INTENT_MOVE:
            return NSFileCoordinatorWritingForMoving;
        case ZTD_MAC_INTENT_REPLACE:
            return NSFileCoordinatorWritingForReplacing;
        default:
            return 0;
    }
}

static int32_t ztd_invoke_accessor(
    ztd_mac_accessor accessor,
    void *context,
    NSURL *first,
    NSURL *second) {
    const char *first_path = first.fileSystemRepresentation;
    const char *second_path = second == nil ? NULL : second.fileSystemRepresentation;
    if (first_path == NULL || (second != nil && second_path == NULL)) {
        return -1;
    }
    return accessor(
        context,
        (const uint8_t *)first_path,
        strlen(first_path),
        (const uint8_t *)second_path,
        second_path == NULL ? 0 : strlen(second_path));
}

static NSFileCoordinator *ztd_new_coordinator(
    const uint8_t *purpose,
    size_t purpose_len,
    ztd_mac_error *error) {
    NSString *identifier = ztd_purpose_identifier(purpose, purpose_len, error);
    if (identifier == nil) {
        return nil;
    }
    NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
    coordinator.purposeIdentifier = identifier;
    return coordinator;
}

static int32_t ztd_mac_coordinate_one_impl(
    const uint8_t *purpose,
    size_t purpose_len,
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    int32_t intent,
    ztd_mac_accessor accessor,
    void *context,
    ztd_mac_error *error) {
    ztd_clear_error(error);
    if (accessor == NULL || !ztd_valid_intent(intent) || intent == ZTD_MAC_INTENT_MOVE) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"one-item coordination cannot express a move destination");
        return -1;
    }

    @try {
        NSURL *url = ztd_file_url(path, path_len, is_directory, error);
        NSFileCoordinator *coordinator = ztd_new_coordinator(purpose, purpose_len, error);
        if (url == nil || coordinator == nil) {
            return -1;
        }

        __block int32_t accessor_status = INT32_MIN;
        NSError *coordination_error = nil;
        if (intent == ZTD_MAC_INTENT_READ) {
            [coordinator coordinateReadingItemAtURL:url
                                           options:0
                                             error:&coordination_error
                                        byAccessor:^(NSURL *adjusted_url) {
                accessor_status = ztd_invoke_accessor(accessor, context, adjusted_url, nil);
            }];
        } else {
            [coordinator coordinateWritingItemAtURL:url
                                           options:ztd_writing_options(intent)
                                             error:&coordination_error
                                        byAccessor:^(NSURL *adjusted_url) {
                accessor_status = ztd_invoke_accessor(accessor, context, adjusted_url, nil);
            }];
        }

        if (coordination_error != nil) {
            ztd_set_foundation_error(error, coordination_error);
            return -1;
        }
        if (accessor_status != 0) {
            ztd_set_error(
                error,
                ZTD_MAC_ERROR_ACCESSOR,
                accessor_status,
                @"zerotrust-drive",
                accessor_status == INT32_MIN
                    ? @"Foundation returned without invoking the coordinated accessor"
                    : @"the coordinated accessor rejected the operation");
            return -1;
        }
        return 0;
    } @catch (NSException *exception) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_EXCEPTION,
            0,
            exception.name,
            exception.reason);
        return -1;
    }
}

static int32_t ztd_mac_coordinate_two_impl(
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
    ztd_mac_error *error) {
    ztd_clear_error(error);
    if (accessor == NULL || !ztd_valid_intent(first_intent) ||
        !ztd_valid_intent(second_intent) || first_intent == ZTD_MAC_INTENT_MOVE ||
        second_intent == ZTD_MAC_INTENT_MOVE ||
        (first_intent == ZTD_MAC_INTENT_READ && second_intent == ZTD_MAC_INTENT_READ)) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"generic two-item coordination requires a non-move write intent");
        return -1;
    }

    @try {
        NSURL *first = ztd_file_url(first_path, first_path_len, first_is_directory, error);
        NSURL *second = ztd_file_url(second_path, second_path_len, second_is_directory, error);
        NSFileCoordinator *coordinator = ztd_new_coordinator(purpose, purpose_len, error);
        if (first == nil || second == nil || coordinator == nil) {
            return -1;
        }

        __block int32_t accessor_status = INT32_MIN;
        __block NSError *coordination_error = nil;
        BOOL first_writes = ztd_is_write_intent(first_intent);
        BOOL second_writes = ztd_is_write_intent(second_intent);

        if (!first_writes && second_writes) {
            [coordinator coordinateReadingItemAtURL:first
                                           options:0
                                  writingItemAtURL:second
                                           options:ztd_writing_options(second_intent)
                                             error:&coordination_error
                                        byAccessor:^(NSURL *adjusted_first, NSURL *adjusted_second) {
                accessor_status = ztd_invoke_accessor(
                    accessor, context, adjusted_first, adjusted_second);
            }];
        } else if (first_writes && !second_writes) {
            [coordinator coordinateReadingItemAtURL:second
                                           options:0
                                  writingItemAtURL:first
                                           options:ztd_writing_options(first_intent)
                                             error:&coordination_error
                                        byAccessor:^(NSURL *adjusted_second, NSURL *adjusted_first) {
                accessor_status = ztd_invoke_accessor(
                    accessor, context, adjusted_first, adjusted_second);
            }];
        } else {
            [coordinator coordinateWritingItemAtURL:first
                                           options:ztd_writing_options(first_intent)
                                  writingItemAtURL:second
                                           options:ztd_writing_options(second_intent)
                                             error:&coordination_error
                                        byAccessor:^(NSURL *adjusted_first, NSURL *adjusted_second) {
                accessor_status = ztd_invoke_accessor(
                    accessor, context, adjusted_first, adjusted_second);
            }];
        }

        if (coordination_error != nil) {
            ztd_set_foundation_error(error, coordination_error);
            return -1;
        }
        if (accessor_status != 0) {
            ztd_set_error(
                error,
                ZTD_MAC_ERROR_ACCESSOR,
                accessor_status,
                @"zerotrust-drive",
                accessor_status == INT32_MIN
                    ? @"Foundation returned without invoking the coordinated accessor"
                    : @"the coordinated accessor rejected the operation");
            return -1;
        }
        return 0;
    } @catch (NSException *exception) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_EXCEPTION,
            0,
            exception.name,
            exception.reason);
        return -1;
    }
}

static int32_t ztd_mac_coordinate_move_impl(
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
    ztd_mac_error *error) {
    ztd_clear_error(error);
    if (accessor == NULL || source_is_directory != destination_is_directory) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"a coordinated move requires one source and same-kind destination");
        return -1;
    }

    @try {
        NSURL *source =
            ztd_file_url(source_path, source_path_len, source_is_directory, error);
        NSURL *destination = ztd_file_url(
            destination_path,
            destination_path_len,
            destination_is_directory,
            error);
        NSFileCoordinator *coordinator = ztd_new_coordinator(purpose, purpose_len, error);
        if (source == nil || destination == nil || coordinator == nil) {
            return -1;
        }

        __block int32_t accessor_status = INT32_MIN;
        NSError *coordination_error = nil;
        [coordinator coordinateWritingItemAtURL:source
                                       options:NSFileCoordinatorWritingForMoving
                              writingItemAtURL:destination
                                       options:NSFileCoordinatorWritingForReplacing
                                         error:&coordination_error
                                    byAccessor:^(NSURL *adjusted_source,
                                                 NSURL *adjusted_destination) {
            [coordinator itemAtURL:adjusted_source willMoveToURL:adjusted_destination];
            accessor_status = ztd_invoke_accessor(
                accessor, context, adjusted_source, adjusted_destination);
            if (accessor_status == ZTD_MAC_ACCESSOR_OK ||
                accessor_status == ZTD_MAC_ACCESSOR_FAILED_AFTER_MOVE) {
                [coordinator itemAtURL:adjusted_source didMoveToURL:adjusted_destination];
            }
        }];

        if (coordination_error != nil) {
            ztd_set_foundation_error(error, coordination_error);
            return -1;
        }
        if (accessor_status != ZTD_MAC_ACCESSOR_OK) {
            ztd_set_error(
                error,
                ZTD_MAC_ERROR_ACCESSOR,
                accessor_status,
                @"zerotrust-drive",
                accessor_status == INT32_MIN
                    ? @"Foundation returned without invoking the coordinated move accessor"
                    : @"the coordinated move accessor rejected the operation");
            return -1;
        }
        return 0;
    } @catch (NSException *exception) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_EXCEPTION,
            0,
            exception.name,
            exception.reason);
        return -1;
    }
}

static void ztd_copy_embedded_error(char *destination, NSError *error) {
    if (error == nil) {
        destination[0] = '\0';
        return;
    }
    NSString *description = [NSString stringWithFormat:@"%@: %ld: %@",
                                                       error.domain,
                                                       (long)error.code,
                                                       error.localizedDescription];
    ztd_copy_string(destination, ZTD_MAC_ERROR_MESSAGE_CAPACITY, description);
}

static int32_t ztd_mac_query_ubiquity_impl(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_ubiquity_status *status,
    ztd_mac_error *error) {
    ztd_clear_error(error);
    if (status == NULL) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_INVALID_INPUT,
            0,
            @"zerotrust-drive",
            @"ubiquity query requires an output status");
        return -1;
    }
    memset(status, 0, sizeof(*status));
    status->is_uploaded = -1;
    status->has_unresolved_conflicts = -1;

    @try {
        NSURL *url = ztd_file_url(path, path_len, is_directory, error);
        if (url == nil) {
            return -1;
        }
        NSError *resource_error = nil;
        NSDictionary<NSURLResourceKey, id> *identity =
            [url resourceValuesForKeys:@[ NSURLIsUbiquitousItemKey ] error:&resource_error];
        if (identity == nil || resource_error != nil) {
            ztd_set_foundation_error(error, resource_error);
            return -1;
        }
        status->is_ubiquitous = [identity[NSURLIsUbiquitousItemKey] boolValue] ? 1 : 0;
        if (status->is_ubiquitous == 0) {
            status->download_status = ZTD_MAC_DOWNLOAD_NOT_APPLICABLE;
            return 0;
        }

        NSArray<NSURLResourceKey> *keys = @[
            NSURLUbiquitousItemDownloadingStatusKey,
            NSURLUbiquitousItemDownloadRequestedKey,
            NSURLUbiquitousItemIsDownloadingKey,
            NSURLUbiquitousItemDownloadingErrorKey,
            NSURLUbiquitousItemIsUploadedKey,
            NSURLUbiquitousItemIsUploadingKey,
            NSURLUbiquitousItemUploadingErrorKey,
            NSURLUbiquitousItemHasUnresolvedConflictsKey,
        ];
        NSDictionary<NSURLResourceKey, id> *values =
            [url resourceValuesForKeys:keys error:&resource_error];
        if (values == nil || resource_error != nil) {
            ztd_set_foundation_error(error, resource_error);
            return -1;
        }

        NSString *download_status = values[NSURLUbiquitousItemDownloadingStatusKey];
        if ([download_status isEqualToString:NSURLUbiquitousItemDownloadingStatusCurrent]) {
            status->download_status = ZTD_MAC_DOWNLOAD_CURRENT;
        } else if ([download_status isEqualToString:NSURLUbiquitousItemDownloadingStatusDownloaded]) {
            status->download_status = ZTD_MAC_DOWNLOAD_STALE;
        } else if ([download_status isEqualToString:NSURLUbiquitousItemDownloadingStatusNotDownloaded]) {
            status->download_status = ZTD_MAC_DOWNLOAD_NOT_DOWNLOADED;
        } else {
            status->download_status = ZTD_MAC_DOWNLOAD_UNKNOWN;
        }

        status->download_requested =
            [values[NSURLUbiquitousItemDownloadRequestedKey] boolValue] ? 1 : 0;
        status->is_downloading =
            [values[NSURLUbiquitousItemIsDownloadingKey] boolValue] ? 1 : 0;
        id uploaded = values[NSURLUbiquitousItemIsUploadedKey];
        if ([uploaded isKindOfClass:NSNumber.class]) {
            status->is_uploaded = [uploaded boolValue] ? 1 : 0;
        }
        status->is_uploading =
            [values[NSURLUbiquitousItemIsUploadingKey] boolValue] ? 1 : 0;
        id conflicts = values[NSURLUbiquitousItemHasUnresolvedConflictsKey];
        if ([conflicts isKindOfClass:NSNumber.class]) {
            status->has_unresolved_conflicts = [conflicts boolValue] ? 1 : 0;
        }

        id download_error = values[NSURLUbiquitousItemDownloadingErrorKey];
        if ([download_error isKindOfClass:NSError.class]) {
            ztd_copy_embedded_error(status->download_error, download_error);
        }
        id upload_error = values[NSURLUbiquitousItemUploadingErrorKey];
        if ([upload_error isKindOfClass:NSError.class]) {
            ztd_copy_embedded_error(status->upload_error, upload_error);
        }
        return 0;
    } @catch (NSException *exception) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_EXCEPTION,
            0,
            exception.name,
            exception.reason);
        return -1;
    }
}

static int32_t ztd_mac_start_download_impl(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_error *error) {
    ztd_clear_error(error);
    @try {
        NSURL *url = ztd_file_url(path, path_len, is_directory, error);
        if (url == nil) {
            return -1;
        }
        NSError *download_error = nil;
        BOOL started = [[NSFileManager defaultManager]
            startDownloadingUbiquitousItemAtURL:url
                                          error:&download_error];
        if (!started) {
            ztd_set_foundation_error(error, download_error);
            return -1;
        }
        return 0;
    } @catch (NSException *exception) {
        ztd_set_error(
            error,
            ZTD_MAC_ERROR_EXCEPTION,
            0,
            exception.name,
            exception.reason);
        return -1;
    }
}

int32_t ztd_mac_coordinate_one(
    const uint8_t *purpose,
    size_t purpose_len,
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    int32_t intent,
    ztd_mac_accessor accessor,
    void *context,
    ztd_mac_error *error) {
    @autoreleasepool {
        return ztd_mac_coordinate_one_impl(
            purpose,
            purpose_len,
            path,
            path_len,
            is_directory,
            intent,
            accessor,
            context,
            error);
    }
}

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
    ztd_mac_error *error) {
    @autoreleasepool {
        return ztd_mac_coordinate_two_impl(
            purpose,
            purpose_len,
            first_path,
            first_path_len,
            first_is_directory,
            first_intent,
            second_path,
            second_path_len,
            second_is_directory,
            second_intent,
            accessor,
            context,
            error);
    }
}

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
    ztd_mac_error *error) {
    @autoreleasepool {
        return ztd_mac_coordinate_move_impl(
            purpose,
            purpose_len,
            source_path,
            source_path_len,
            source_is_directory,
            destination_path,
            destination_path_len,
            destination_is_directory,
            accessor,
            context,
            error);
    }
}

int32_t ztd_mac_query_ubiquity(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_ubiquity_status *status,
    ztd_mac_error *error) {
    @autoreleasepool {
        return ztd_mac_query_ubiquity_impl(
            path, path_len, is_directory, status, error);
    }
}

int32_t ztd_mac_start_download(
    const uint8_t *path,
    size_t path_len,
    int32_t is_directory,
    ztd_mac_error *error) {
    @autoreleasepool {
        return ztd_mac_start_download_impl(path, path_len, is_directory, error);
    }
}
