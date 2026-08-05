// Copyright 2026 Alex O <info@lifub.com>
//
// Swift implementation of the macOS file-coordination shim. The C ABI is
// declared in macos_file_coordination.h and consumed by Rust (storage.rs and
// macos_integration_tests.rs); every @_cdecl export below must match those
// prototypes exactly. All Foundation work runs inside
// ztd_mac_exception_guard (macos_exception_guard.m) because Swift cannot
// catch the NSExceptions Foundation raises on misuse, and an exception
// crossing the Rust boundary is undefined behavior. Validation that cannot
// raise runs before the guard so its exact error contract is preserved.
//
// Two defensive Objective-C branches are unreachable here and are therefore
// not ported: a nil return from +[NSURL fileURLWithFileSystemRepresentation:]
// and a NULL -[NSURL fileSystemRepresentation] (both are nonnull API
// contracts whose failure Foundation signals by raising, which the guard
// converts), and the explicit SIZE_MAX/malloc-failure path (Swift allocation
// has no recoverable failure; lengths at or above 2^63 fail the same
// nonempty-path validation instead).

import Foundation

// MARK: - Error-kind constants (mirrors macos_file_coordination.h)

private let errorFoundation = Int32(ZTD_MAC_ERROR_FOUNDATION)
private let errorAccessor = Int32(ZTD_MAC_ERROR_ACCESSOR)
private let errorException = Int32(ZTD_MAC_ERROR_EXCEPTION)
private let errorInvalidInput = Int32(ZTD_MAC_ERROR_INVALID_INPUT)
private let errorTimeout = Int32(ZTD_MAC_ERROR_TIMEOUT)

private let intentRead = Int32(ZTD_MAC_INTENT_READ)
private let intentWrite = Int32(ZTD_MAC_INTENT_WRITE)
private let intentDelete = Int32(ZTD_MAC_INTENT_DELETE)
private let intentMove = Int32(ZTD_MAC_INTENT_MOVE)
private let intentReplace = Int32(ZTD_MAC_INTENT_REPLACE)

private let downloadNotApplicable = Int32(ZTD_MAC_DOWNLOAD_NOT_APPLICABLE)
private let downloadCurrent = Int32(ZTD_MAC_DOWNLOAD_CURRENT)
private let downloadStale = Int32(ZTD_MAC_DOWNLOAD_STALE)
private let downloadNotDownloaded = Int32(ZTD_MAC_DOWNLOAD_NOT_DOWNLOADED)
private let downloadUnknown = Int32(ZTD_MAC_DOWNLOAD_UNKNOWN)

private let accessorOk = Int32(ZTD_MAC_ACCESSOR_OK)
private let accessorFailedAfterMove = Int32(ZTD_MAC_ACCESSOR_FAILED_AFTER_MOVE)

// MARK: - Structured-error helpers

private func copyCString(_ value: String?, into buffer: UnsafeMutableRawBufferPointer) {
    guard let base = buffer.baseAddress, !buffer.isEmpty else {
        return
    }
    memset(base, 0, buffer.count)
    guard let value, !value.isEmpty else {
        return
    }
    let utf8 = Array(value.utf8)
    let length = min(utf8.count, buffer.count - 1)
    utf8.withUnsafeBytes { source in
        _ = memcpy(base, source.baseAddress!, length)
    }
}

private func clearError(_ errorPointer: UnsafeMutablePointer<ztd_mac_error>?) {
    errorPointer?.pointee = ztd_mac_error()
}

private func setError(
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?,
    kind: Int32,
    code: Int64,
    domain: String?,
    message: String?
) {
    guard let errorPointer else {
        return
    }
    errorPointer.pointee = ztd_mac_error()
    errorPointer.pointee.kind = kind
    errorPointer.pointee.code = code
    withUnsafeMutableBytes(of: &errorPointer.pointee.domain) {
        copyCString(domain, into: $0)
    }
    withUnsafeMutableBytes(of: &errorPointer.pointee.message) {
        copyCString(message, into: $0)
    }
}

private func setFoundationError(
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?,
    _ foundationError: NSError?
) {
    setError(
        errorPointer,
        kind: errorFoundation,
        code: Int64(foundationError?.code ?? 0),
        domain: foundationError?.domain,
        message: foundationError?.localizedDescription)
}

private func nativeErrorText(of buffer: UnsafeRawBufferPointer) -> String {
    let bytes = buffer.prefix { $0 != 0 }
    return String(decoding: bytes, as: UTF8.self)
}

// Runs `body` under the Objective-C @try/@catch guard. On a raised
// NSException the guard overwrites `errorPointer` with the structured
// exception error and returns -1; otherwise it returns `body`'s result and
// never touches `errorPointer`.
private func withExceptionGuard(
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?,
    _ body: @escaping () -> Int32
) -> Int32 {
    ztd_mac_exception_guard(body, errorPointer)
}

// MARK: - Input helpers

private func fileURL(
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> NSURL? {
    guard let path, pathLength > 0, memchr(path, 0, pathLength) == nil else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "file coordination requires a nonempty NUL-free filesystem path")
        return nil
    }
    var terminated = [CChar](repeating: 0, count: pathLength + 1)
    terminated.withUnsafeMutableBytes { destination in
        _ = memcpy(destination.baseAddress!, path, pathLength)
    }
    return NSURL(
        fileURLWithFileSystemRepresentation: terminated,
        isDirectory: isDirectory != 0,
        relativeTo: nil)
}

private func purposeIdentifier(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> String? {
    guard let purpose, purposeLength > 0, memchr(purpose, 0, purposeLength) == nil else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "file coordination requires a nonempty NUL-free purpose identifier")
        return nil
    }
    let bytes = UnsafeBufferPointer(start: purpose, count: purposeLength)
    guard let identifier = String(bytes: bytes, encoding: .utf8), !identifier.isEmpty else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "file coordination purpose identifier is not valid UTF-8")
        return nil
    }
    return identifier
}

private func isWriteIntent(_ intent: Int32) -> Bool {
    intent == intentWrite || intent == intentDelete || intent == intentMove
        || intent == intentReplace
}

private func isValidIntent(_ intent: Int32) -> Bool {
    intent == intentRead || isWriteIntent(intent)
}

private func writingOptions(_ intent: Int32) -> NSFileCoordinator.WritingOptions {
    switch intent {
    case intentDelete:
        return .forDeleting
    case intentMove:
        return .forMoving
    case intentReplace:
        return .forReplacing
    default:
        return []
    }
}

private func invokeAccessor(
    _ accessor: ztd_mac_accessor,
    _ context: UnsafeMutableRawPointer?,
    _ first: NSURL,
    _ second: NSURL?
) -> Int32 {
    withExtendedLifetime((first, second)) {
        let firstRepresentation = first.fileSystemRepresentation
        let firstBytes = UnsafeRawPointer(firstRepresentation)
            .assumingMemoryBound(to: UInt8.self)
        let firstLength = strlen(firstRepresentation)
        guard let second else {
            return accessor(context, firstBytes, firstLength, nil, 0)
        }
        let secondRepresentation = second.fileSystemRepresentation
        let secondBytes = UnsafeRawPointer(secondRepresentation)
            .assumingMemoryBound(to: UInt8.self)
        let secondLength = strlen(secondRepresentation)
        return accessor(context, firstBytes, firstLength, secondBytes, secondLength)
    }
}

private func newCoordinator(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> NSFileCoordinator? {
    guard let identifier = purposeIdentifier(purpose, purposeLength, errorPointer) else {
        return nil
    }
    let coordinator = NSFileCoordinator(filePresenter: nil)
    coordinator.purposeIdentifier = identifier
    return coordinator
}

// MARK: - Coordination implementations

private func coordinateOneImpl(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ intent: Int32,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    clearError(errorPointer)
    guard let accessor, isValidIntent(intent), intent != intentMove else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "one-item coordination cannot express a move destination")
        return -1
    }

    return withExceptionGuard(errorPointer) {
        guard let url = fileURL(path, pathLength, isDirectory, errorPointer),
            let coordinator = newCoordinator(purpose, purposeLength, errorPointer)
        else {
            return -1
        }

        var accessorStatus = Int32.min
        var coordinationError: NSError?
        if intent == intentRead {
            coordinator.coordinate(
                readingItemAt: url as URL,
                options: [],
                error: &coordinationError
            ) { adjustedURL in
                accessorStatus = invokeAccessor(accessor, context, adjustedURL as NSURL, nil)
            }
        } else {
            coordinator.coordinate(
                writingItemAt: url as URL,
                options: writingOptions(intent),
                error: &coordinationError
            ) { adjustedURL in
                accessorStatus = invokeAccessor(accessor, context, adjustedURL as NSURL, nil)
            }
        }

        if let coordinationError {
            setFoundationError(errorPointer, coordinationError)
            return -1
        }
        if accessorStatus != 0 {
            setError(
                errorPointer,
                kind: errorAccessor,
                code: Int64(accessorStatus),
                domain: "zerotrust-drive",
                message: accessorStatus == Int32.min
                    ? "Foundation returned without invoking the coordinated accessor"
                    : "the coordinated accessor rejected the operation")
            return -1
        }
        return 0
    }
}

private func coordinateTwoImpl(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ firstPath: UnsafePointer<UInt8>?,
    _ firstPathLength: Int,
    _ firstIsDirectory: Int32,
    _ firstIntent: Int32,
    _ secondPath: UnsafePointer<UInt8>?,
    _ secondPathLength: Int,
    _ secondIsDirectory: Int32,
    _ secondIntent: Int32,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    clearError(errorPointer)
    guard let accessor, isValidIntent(firstIntent), isValidIntent(secondIntent),
        firstIntent != intentMove, secondIntent != intentMove,
        !(firstIntent == intentRead && secondIntent == intentRead)
    else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "generic two-item coordination requires a non-move write intent")
        return -1
    }

    return withExceptionGuard(errorPointer) {
        guard let first = fileURL(firstPath, firstPathLength, firstIsDirectory, errorPointer),
            let second = fileURL(secondPath, secondPathLength, secondIsDirectory, errorPointer),
            let coordinator = newCoordinator(purpose, purposeLength, errorPointer)
        else {
            return -1
        }

        var accessorStatus = Int32.min
        var coordinationError: NSError?
        let firstWrites = isWriteIntent(firstIntent)
        let secondWrites = isWriteIntent(secondIntent)

        if !firstWrites && secondWrites {
            coordinator.coordinate(
                readingItemAt: first as URL,
                options: [],
                writingItemAt: second as URL,
                options: writingOptions(secondIntent),
                error: &coordinationError
            ) { adjustedFirst, adjustedSecond in
                accessorStatus = invokeAccessor(
                    accessor, context, adjustedFirst as NSURL, adjustedSecond as NSURL)
            }
        } else if firstWrites && !secondWrites {
            coordinator.coordinate(
                readingItemAt: second as URL,
                options: [],
                writingItemAt: first as URL,
                options: writingOptions(firstIntent),
                error: &coordinationError
            ) { adjustedSecond, adjustedFirst in
                accessorStatus = invokeAccessor(
                    accessor, context, adjustedFirst as NSURL, adjustedSecond as NSURL)
            }
        } else {
            coordinator.coordinate(
                writingItemAt: first as URL,
                options: writingOptions(firstIntent),
                writingItemAt: second as URL,
                options: writingOptions(secondIntent),
                error: &coordinationError
            ) { adjustedFirst, adjustedSecond in
                accessorStatus = invokeAccessor(
                    accessor, context, adjustedFirst as NSURL, adjustedSecond as NSURL)
            }
        }

        if let coordinationError {
            setFoundationError(errorPointer, coordinationError)
            return -1
        }
        if accessorStatus != 0 {
            setError(
                errorPointer,
                kind: errorAccessor,
                code: Int64(accessorStatus),
                domain: "zerotrust-drive",
                message: accessorStatus == Int32.min
                    ? "Foundation returned without invoking the coordinated accessor"
                    : "the coordinated accessor rejected the operation")
            return -1
        }
        return 0
    }
}

private func coordinateMoveImpl(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ sourcePath: UnsafePointer<UInt8>?,
    _ sourcePathLength: Int,
    _ sourceIsDirectory: Int32,
    _ destinationPath: UnsafePointer<UInt8>?,
    _ destinationPathLength: Int,
    _ destinationIsDirectory: Int32,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    clearError(errorPointer)
    guard let accessor, sourceIsDirectory == destinationIsDirectory else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "a coordinated move requires one source and same-kind destination")
        return -1
    }

    return withExceptionGuard(errorPointer) {
        guard
            let source = fileURL(sourcePath, sourcePathLength, sourceIsDirectory, errorPointer),
            let destination = fileURL(
                destinationPath, destinationPathLength, destinationIsDirectory, errorPointer),
            let coordinator = newCoordinator(purpose, purposeLength, errorPointer)
        else {
            return -1
        }

        var accessorStatus = Int32.min
        var coordinationError: NSError?
        coordinator.coordinate(
            writingItemAt: source as URL,
            options: .forMoving,
            writingItemAt: destination as URL,
            options: .forReplacing,
            error: &coordinationError
        ) { adjustedSource, adjustedDestination in
            coordinator.item(at: adjustedSource, willMoveTo: adjustedDestination)
            accessorStatus = invokeAccessor(
                accessor, context, adjustedSource as NSURL, adjustedDestination as NSURL)
            if accessorStatus == accessorOk || accessorStatus == accessorFailedAfterMove {
                coordinator.item(at: adjustedSource, didMoveTo: adjustedDestination)
            }
        }

        if let coordinationError {
            setFoundationError(errorPointer, coordinationError)
            return -1
        }
        if accessorStatus != accessorOk {
            setError(
                errorPointer,
                kind: errorAccessor,
                code: Int64(accessorStatus),
                domain: "zerotrust-drive",
                message: accessorStatus == Int32.min
                    ? "Foundation returned without invoking the coordinated move accessor"
                    : "the coordinated move accessor rejected the operation")
            return -1
        }
        return 0
    }
}

// MARK: - Ubiquity queries

private func copyEmbeddedError(
    _ embedded: NSError?,
    into buffer: UnsafeMutableRawBufferPointer
) {
    guard let embedded else {
        copyCString(nil, into: buffer)
        return
    }
    let description = "\(embedded.domain): \(embedded.code): \(embedded.localizedDescription)"
    copyCString(description, into: buffer)
}

private func queryUbiquityImpl(
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ statusPointer: UnsafeMutablePointer<ztd_mac_ubiquity_status>?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    clearError(errorPointer)
    guard let statusPointer else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "ubiquity query requires an output status")
        return -1
    }
    statusPointer.pointee = ztd_mac_ubiquity_status()
    statusPointer.pointee.is_uploaded = -1
    statusPointer.pointee.has_unresolved_conflicts = -1

    return withExceptionGuard(errorPointer) {
        guard let url = fileURL(path, pathLength, isDirectory, errorPointer) else {
            return -1
        }

        let identity: [URLResourceKey: Any]
        do {
            identity = try url.resourceValues(forKeys: [.isUbiquitousItemKey])
        } catch let caught as NSError {
            setFoundationError(errorPointer, caught)
            return -1
        }
        let isUbiquitous = (identity[.isUbiquitousItemKey] as? NSNumber)?.boolValue ?? false
        statusPointer.pointee.is_ubiquitous = isUbiquitous ? 1 : 0
        if !isUbiquitous {
            statusPointer.pointee.download_status = downloadNotApplicable
            return 0
        }

        let keys: [URLResourceKey] = [
            .ubiquitousItemDownloadingStatusKey,
            .ubiquitousItemDownloadRequestedKey,
            .ubiquitousItemIsDownloadingKey,
            .ubiquitousItemDownloadingErrorKey,
            .ubiquitousItemIsUploadedKey,
            .ubiquitousItemIsUploadingKey,
            .ubiquitousItemUploadingErrorKey,
            .ubiquitousItemHasUnresolvedConflictsKey,
        ]
        let values: [URLResourceKey: Any]
        do {
            values = try url.resourceValues(forKeys: keys)
        } catch let caught as NSError {
            setFoundationError(errorPointer, caught)
            return -1
        }

        let downloadingStatus = values[.ubiquitousItemDownloadingStatusKey] as? String
        if downloadingStatus == URLUbiquitousItemDownloadingStatus.current.rawValue {
            statusPointer.pointee.download_status = downloadCurrent
        } else if downloadingStatus == URLUbiquitousItemDownloadingStatus.downloaded.rawValue {
            statusPointer.pointee.download_status = downloadStale
        } else if downloadingStatus == URLUbiquitousItemDownloadingStatus.notDownloaded.rawValue {
            statusPointer.pointee.download_status = downloadNotDownloaded
        } else {
            statusPointer.pointee.download_status = downloadUnknown
        }

        statusPointer.pointee.download_requested =
            (values[.ubiquitousItemDownloadRequestedKey] as? NSNumber)?.boolValue ?? false
                ? 1 : 0
        statusPointer.pointee.is_downloading =
            (values[.ubiquitousItemIsDownloadingKey] as? NSNumber)?.boolValue ?? false ? 1 : 0
        if let uploaded = values[.ubiquitousItemIsUploadedKey] as? NSNumber {
            statusPointer.pointee.is_uploaded = uploaded.boolValue ? 1 : 0
        }
        statusPointer.pointee.is_uploading =
            (values[.ubiquitousItemIsUploadingKey] as? NSNumber)?.boolValue ?? false ? 1 : 0
        if let conflicts = values[.ubiquitousItemHasUnresolvedConflictsKey] as? NSNumber {
            statusPointer.pointee.has_unresolved_conflicts = conflicts.boolValue ? 1 : 0
        }

        if let downloadError = values[.ubiquitousItemDownloadingErrorKey] as? NSError {
            withUnsafeMutableBytes(of: &statusPointer.pointee.download_error) {
                copyEmbeddedError(downloadError, into: $0)
            }
        }
        if let uploadError = values[.ubiquitousItemUploadingErrorKey] as? NSError {
            withUnsafeMutableBytes(of: &statusPointer.pointee.upload_error) {
                copyEmbeddedError(uploadError, into: $0)
            }
        }
        return 0
    }
}

private func startDownloadImpl(
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    clearError(errorPointer)
    return withExceptionGuard(errorPointer) {
        guard let url = fileURL(path, pathLength, isDirectory, errorPointer) else {
            return -1
        }
        do {
            try FileManager.default.startDownloadingUbiquitousItem(at: url as URL)
        } catch let caught as NSError {
            setFoundationError(errorPointer, caught)
            return -1
        }
        return 0
    }
}

private func evictUbiquitousItemImpl(
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    clearError(errorPointer)
    return withExceptionGuard(errorPointer) {
        guard let url = fileURL(path, pathLength, isDirectory, errorPointer) else {
            return -1
        }
        do {
            try FileManager.default.evictUbiquitousItem(at: url as URL)
        } catch let caught as NSError {
            setFoundationError(errorPointer, caught)
            return -1
        }
        return 0
    }
}

// MARK: - NSFilePresenter move probe

private final class ZTDMovePresenterProbe: NSObject, NSFilePresenter {
    private let stateLock = NSLock()
    private let moveSemaphore = DispatchSemaphore(value: 0)
    private let queue: OperationQueue
    private var url: NSURL
    private var relinquishWriterCount: Int32 = 0
    private var moveCount: Int32 = 0
    private var observedDestination: NSURL?
    private var callbackFailure: (name: String, reason: String)?

    init(url: NSURL) {
        self.url = url.copy() as? NSURL ?? url
        queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.name = "net.lifub.zerotrust-drive.presenter-probe"
        super.init()
    }

    var presentedItemURL: URL? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return url as URL
    }

    var presentedItemOperationQueue: OperationQueue {
        queue
    }

    func relinquishPresentedItem(
        toWriter writer: @escaping @Sendable ((@Sendable () -> Void)?) -> Void
    ) {
        var guardError = ztd_mac_error()
        let status = withExceptionGuard(&guardError) { [self] in
            stateLock.lock()
            relinquishWriterCount += 1
            stateLock.unlock()
            writer(nil)
            return 0
        }
        if status != 0 {
            recordCallbackFailure(from: &guardError)
        }
    }

    func presentedItemDidMove(to newURL: URL) {
        var guardError = ztd_mac_error()
        let status = withExceptionGuard(&guardError) { [self] in
            let bridged = newURL as NSURL
            let presented = bridged.copy() as? NSURL ?? bridged
            let observed = bridged.copy() as? NSURL ?? bridged
            stateLock.lock()
            url = presented
            observedDestination = observed
            moveCount += 1
            stateLock.unlock()
            moveSemaphore.signal()
            return 0
        }
        if status != 0 {
            recordCallbackFailure(from: &guardError)
        }
    }

    // Recording is exception-free by construction (NSLock, String, semaphore),
    // matching the Objective-C recordCallbackException: whose @finally always
    // signaled the move semaphore so a failed callback cannot hang the wait.
    private func recordCallbackFailure(from guardError: inout ztd_mac_error) {
        let name = withUnsafeBytes(of: guardError.domain) { nativeErrorText(of: $0) }
        let reason = withUnsafeBytes(of: guardError.message) { nativeErrorText(of: $0) }
        stateLock.lock()
        callbackFailure = (name: name, reason: reason)
        stateLock.unlock()
        moveSemaphore.signal()
    }

    func waitForMove(timeoutMilliseconds: UInt64) -> Bool {
        guard let deadline = dispatchDeadline(timeoutMilliseconds: timeoutMilliseconds) else {
            return false
        }
        return moveSemaphore.wait(timeout: deadline) == .success
    }

    // Removal prevents new callbacks. A queued barrier observes completion
    // without allowing a stuck callback to hang this test process forever.
    func waitForQueueDrain(timeoutMilliseconds: UInt64) -> Bool {
        guard let deadline = dispatchDeadline(timeoutMilliseconds: timeoutMilliseconds) else {
            return false
        }
        let drained = DispatchSemaphore(value: 0)
        queue.addBarrierBlock {
            drained.signal()
        }
        return drained.wait(timeout: deadline) == .success
    }

    private func dispatchDeadline(timeoutMilliseconds: UInt64) -> DispatchTime? {
        guard timeoutMilliseconds <= UInt64(Int64.max) / NSEC_PER_MSEC else {
            return nil
        }
        let nanoseconds = Int64(timeoutMilliseconds) * Int64(NSEC_PER_MSEC)
        return DispatchTime.now() + .nanoseconds(Int(nanoseconds))
    }

    func snapshotCallbackFailure() -> (name: String, reason: String)? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return callbackFailure
    }

    func snapshotCounters() -> (
        relinquishWriterCount: Int32, moveCount: Int32, observedDestination: NSURL?
    ) {
        stateLock.lock()
        defer { stateLock.unlock() }
        return (relinquishWriterCount, moveCount, observedDestination?.copy() as? NSURL)
    }
}

private func probeCoordinatedMoveImpl(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ sourcePath: UnsafePointer<UInt8>?,
    _ sourcePathLength: Int,
    _ sourceIsDirectory: Int32,
    _ destinationPath: UnsafePointer<UInt8>?,
    _ destinationPathLength: Int,
    _ destinationIsDirectory: Int32,
    _ timeoutMilliseconds: UInt64,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ resultPointer: UnsafeMutablePointer<ztd_mac_presenter_probe_result>?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    clearError(errorPointer)
    guard let resultPointer, timeoutMilliseconds != 0 else {
        setError(
            errorPointer,
            kind: errorInvalidInput,
            code: 0,
            domain: "zerotrust-drive",
            message: "presenter probe requires an output result and a nonzero timeout")
        return -1
    }
    resultPointer.pointee = ztd_mac_presenter_probe_result()

    var registered = false
    var outcome: Int32 = -1
    var probe: ZTDMovePresenterProbe?
    var destination: NSURL?

    let attemptStatus = withExceptionGuard(errorPointer) {
        guard
            let source = fileURL(sourcePath, sourcePathLength, sourceIsDirectory, errorPointer),
            let destinationURL = fileURL(
                destinationPath, destinationPathLength, destinationIsDirectory, errorPointer)
        else {
            return -1
        }
        destination = destinationURL

        let presenterProbe = ZTDMovePresenterProbe(url: source)
        probe = presenterProbe
        NSFileCoordinator.addFilePresenter(presenterProbe)
        registered = true

        if coordinateMoveImpl(
            purpose,
            purposeLength,
            sourcePath,
            sourcePathLength,
            sourceIsDirectory,
            destinationPath,
            destinationPathLength,
            destinationIsDirectory,
            accessor,
            context,
            errorPointer) != 0
        {
            return -1
        }

        guard presenterProbe.waitForMove(timeoutMilliseconds: timeoutMilliseconds) else {
            setError(
                errorPointer,
                kind: errorTimeout,
                code: Int64(ETIMEDOUT),
                domain: NSPOSIXErrorDomain,
                message: "timed out waiting for NSFilePresenter move notification")
            return -1
        }

        outcome = 0
        return 0
    }
    if attemptStatus != 0 {
        outcome = -1
    }

    // The Objective-C @finally equivalent: always unregister and drain when
    // registration happened, preserving the original attempt error unless the
    // cleanup itself fails.
    if registered, let presenterProbe = probe {
        let cleanupStatus = withExceptionGuard(errorPointer) {
            NSFileCoordinator.removeFilePresenter(presenterProbe)
            let drained = presenterProbe.waitForQueueDrain(
                timeoutMilliseconds: timeoutMilliseconds)
            if !drained && outcome == 0 {
                setError(
                    errorPointer,
                    kind: errorTimeout,
                    code: Int64(ETIMEDOUT),
                    domain: NSPOSIXErrorDomain,
                    message: "timed out draining the NSFilePresenter callback queue")
                outcome = -1
            }
            if drained, let failure = presenterProbe.snapshotCallbackFailure(), outcome == 0 {
                setError(
                    errorPointer,
                    kind: errorException,
                    code: 0,
                    domain: failure.name,
                    message: failure.reason)
                outcome = -1
            }
            return 0
        }
        if cleanupStatus != 0 {
            outcome = -1
        }
    }
    if outcome != 0 {
        return -1
    }

    return withExceptionGuard(errorPointer) {
        guard let presenterProbe = probe, let destination else {
            // Unreachable: outcome == 0 requires a registered probe and URLs.
            return -1
        }
        let snapshot = presenterProbe.snapshotCounters()
        resultPointer.pointee.relinquish_writer_count = snapshot.relinquishWriterCount
        resultPointer.pointee.move_count = snapshot.moveCount

        let observed = snapshot.observedDestination
        let resolvedObserved = (observed as URL?)?.resolvingSymlinksInPath()
        let resolvedExpected = (destination as URL).resolvingSymlinksInPath()
        var matches = false
        if let resolvedObserved {
            withExtendedLifetime((resolvedObserved as NSURL, resolvedExpected as NSURL)) {
                let observedRepresentation = (resolvedObserved as NSURL)
                    .fileSystemRepresentation
                let expectedRepresentation = (resolvedExpected as NSURL)
                    .fileSystemRepresentation
                matches = strcmp(observedRepresentation, expectedRepresentation) == 0
            }
        }
        resultPointer.pointee.destination_matches = matches ? 1 : 0
        if !matches {
            let observedPath = observed?.path ?? "(null)"
            let expectedPath = (destination as URL).path
            setError(
                errorPointer,
                kind: errorAccessor,
                code: 0,
                domain: "zerotrust-drive",
                message:
                    "NSFilePresenter observed move destination \(observedPath) instead of \(expectedPath)")
            return -1
        }
        return 0
    }
}

// MARK: - C ABI exports (contracts in macos_file_coordination.h)

@_cdecl("ztd_mac_coordinate_one")
public func ztdMacCoordinateOne(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ intent: Int32,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        coordinateOneImpl(
            purpose, purposeLength, path, pathLength, isDirectory, intent, accessor, context,
            errorPointer)
    }
}

@_cdecl("ztd_mac_coordinate_two")
public func ztdMacCoordinateTwo(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ firstPath: UnsafePointer<UInt8>?,
    _ firstPathLength: Int,
    _ firstIsDirectory: Int32,
    _ firstIntent: Int32,
    _ secondPath: UnsafePointer<UInt8>?,
    _ secondPathLength: Int,
    _ secondIsDirectory: Int32,
    _ secondIntent: Int32,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        coordinateTwoImpl(
            purpose, purposeLength, firstPath, firstPathLength, firstIsDirectory, firstIntent,
            secondPath, secondPathLength, secondIsDirectory, secondIntent, accessor, context,
            errorPointer)
    }
}

@_cdecl("ztd_mac_coordinate_move")
public func ztdMacCoordinateMove(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ sourcePath: UnsafePointer<UInt8>?,
    _ sourcePathLength: Int,
    _ sourceIsDirectory: Int32,
    _ destinationPath: UnsafePointer<UInt8>?,
    _ destinationPathLength: Int,
    _ destinationIsDirectory: Int32,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        coordinateMoveImpl(
            purpose, purposeLength, sourcePath, sourcePathLength, sourceIsDirectory,
            destinationPath, destinationPathLength, destinationIsDirectory, accessor, context,
            errorPointer)
    }
}

@_cdecl("ztd_mac_query_ubiquity")
public func ztdMacQueryUbiquity(
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ statusPointer: UnsafeMutablePointer<ztd_mac_ubiquity_status>?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        queryUbiquityImpl(path, pathLength, isDirectory, statusPointer, errorPointer)
    }
}

@_cdecl("ztd_mac_start_download")
public func ztdMacStartDownload(
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        startDownloadImpl(path, pathLength, isDirectory, errorPointer)
    }
}

@_cdecl("ztd_mac_evict_ubiquitous_item")
public func ztdMacEvictUbiquitousItem(
    _ path: UnsafePointer<UInt8>?,
    _ pathLength: Int,
    _ isDirectory: Int32,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        evictUbiquitousItemImpl(path, pathLength, isDirectory, errorPointer)
    }
}

@_cdecl("ztd_mac_probe_coordinated_move")
public func ztdMacProbeCoordinatedMove(
    _ purpose: UnsafePointer<UInt8>?,
    _ purposeLength: Int,
    _ sourcePath: UnsafePointer<UInt8>?,
    _ sourcePathLength: Int,
    _ sourceIsDirectory: Int32,
    _ destinationPath: UnsafePointer<UInt8>?,
    _ destinationPathLength: Int,
    _ destinationIsDirectory: Int32,
    _ timeoutMilliseconds: UInt64,
    _ accessor: ztd_mac_accessor?,
    _ context: UnsafeMutableRawPointer?,
    _ resultPointer: UnsafeMutablePointer<ztd_mac_presenter_probe_result>?,
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        probeCoordinatedMoveImpl(
            purpose, purposeLength, sourcePath, sourcePathLength, sourceIsDirectory,
            destinationPath, destinationPathLength, destinationIsDirectory,
            timeoutMilliseconds, accessor, context, resultPointer, errorPointer)
    }
}

// Test-only, mirroring the ztd_mac_evict_ubiquitous_item precedent: proves
// from Rust that an NSException raised beneath Swift frames is contained by
// the Objective-C guard and reported as a structured error.
@_cdecl("ztd_mac_test_exception_containment")
public func ztdMacTestExceptionContainment(
    _ errorPointer: UnsafeMutablePointer<ztd_mac_error>?
) -> Int32 {
    autoreleasepool {
        clearError(errorPointer)
        return withExceptionGuard(errorPointer) {
            ztd_mac_test_raise_foundation_exception()
            return 0
        }
    }
}
