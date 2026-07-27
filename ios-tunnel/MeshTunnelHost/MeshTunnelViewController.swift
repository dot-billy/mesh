import AuthenticationServices
import NetworkExtension
import UIKit

final class MeshTunnelViewController: UIViewController {
    private static let providerBundleIdentifier =
        "io.rw0.mesh.tunnel.mobile.packet-tunnel"
    private static let postAuthorizationManagerReadinessAttempts = 6
    private static let postAuthorizationManagerReadinessDelay =
        Duration.milliseconds(500)
    private static let providerStartObservationAttempts = 180
    private static let providerStartObservationDelay =
        Duration.milliseconds(500)
    private static let disconnectErrorFetchTimeout = 2.0
    private static let providerFailureCodes: Set<String> = [
        "agent-authorization-rejected",
        "configuration-container-unavailable",
        "configuration-invalid",
        "configuration-unavailable",
        "engine-unavailable",
        "enrollment-failed",
        "enrollment-request-rejected",
        "identity-removal-context-mismatch",
        "identity-removal-failed",
        "identity-removal-request-invalid",
        "identity-removed",
        "lifecycle-refresh-failed",
        "mobile-runtime-evidence-failed",
        "mobile-runtime-evidence-invalid",
        "mobile-runtime-evidence-stale",
        "mobile-runtime-refresh-required",
        "network-rebind-failed",
        "packet-flow-failed",
        "start-already-in-progress",
        "start-cancelled",
    ]
    private static let lastSetupStageKey =
        "mesh.selfEnrollment.lastSetupStage"
    private static let lastSetupResultKey =
        "mesh.selfEnrollment.lastSetupResult"

    private let statusLabel = UILabel()
    private let diagnosticLabel = UILabel()
    private let originField = UITextField()
    private let signInButton = UIButton(type: .system)
    private let startButton = UIButton(type: .system)
    private let stopButton = UIButton(type: .system)
    private let inspectButton = UIButton(type: .system)
    private let removeIdentityButton = UIButton(type: .system)
    private let privacyShield = UIView()
    private var preparedManager: NETunnelProviderManager?
    private var preparedOrigin: String?
    private var authorizationSession: ASWebAuthenticationSession?
    private var authorizationWasCancelled = false
    private var isCompletingAuthorization = false
    private var setupFailureIsVisible = false
    private var setupTask: Task<Void, Never>?
    private var inspectionTask: Task<Void, Never>?
    private var inspectionGeneration = 0
    private var activeSetupStage = TunnelAutomaticSetupStage.starting
    private var backgroundCancelledSetup = false
    private var providerStartObservationInProgress = false
    private var enrollmentClient: TunnelUserEnrollmentClient?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let titleLabel = UILabel()
        titleLabel.font = .preferredFont(forTextStyle: .largeTitle)
        titleLabel.adjustsFontForContentSizeCategory = true
        titleLabel.text = "Mesh Tunnel"

        statusLabel.font = .preferredFont(forTextStyle: .body)
        statusLabel.adjustsFontForContentSizeCategory = true
        statusLabel.numberOfLines = 0
        statusLabel.accessibilityLabel = "Mesh Tunnel status"
        statusLabel.text = """
        Enter your Mesh server, then sign in with your own account. Mesh will \
        prepare the Apple VPN configuration and pass a server-issued one-time \
        enrollment token directly to the Packet Tunnel extension.
        """

        diagnosticLabel.font = .preferredFont(forTextStyle: .caption1)
        diagnosticLabel.adjustsFontForContentSizeCategory = true
        diagnosticLabel.numberOfLines = 0
        diagnosticLabel.textColor = .secondaryLabel
        diagnosticLabel.accessibilityLabel = "Mesh Tunnel build and setup stage"
        updateDiagnosticLabel()

        originField.borderStyle = .roundedRect
        originField.placeholder = "https://mesh.example"
        originField.autocapitalizationType = .none
        originField.autocorrectionType = .no
        originField.keyboardType = .URL
        originField.accessibilityLabel = "Mesh control-plane HTTPS origin"

        signInButton.configuration = .filled()
        signInButton.configuration?.title = "Sign in and set up VPN"
        signInButton.addTarget(
            self,
            action: #selector(signInAndSetUpVPN),
            for: .touchUpInside
        )
        signInButton.accessibilityHint = (
            "Opens the Mesh sign-in page, asks Apple to add the VPN "
                + "configuration, and starts enrollment."
        )

        startButton.configuration = .filled()
        startButton.configuration?.title = "Start existing tunnel"
        startButton.isEnabled = false
        startButton.addTarget(
            self,
            action: #selector(startExistingTunnel),
            for: .touchUpInside
        )
        startButton.accessibilityHint = (
            "Starts the authenticated identity already stored by the "
                + "Packet Tunnel extension."
        )

        stopButton.configuration = .bordered()
        stopButton.configuration?.title = "Stop tunnel"
        stopButton.isEnabled = false
        stopButton.addTarget(
            self,
            action: #selector(stopTunnel),
            for: .touchUpInside
        )
        stopButton.accessibilityHint = (
            "Requests that the current Packet Tunnel stop."
        )

        inspectButton.configuration = .bordered()
        inspectButton.configuration?.title = "Inspect installed configuration"
        inspectButton.addTarget(
            self,
            action: #selector(inspectConfiguration),
            for: .touchUpInside
        )
        inspectButton.accessibilityHint = (
            "Reads existing system configuration without installing or "
                + "starting a tunnel."
        )

        removeIdentityButton.configuration = .bordered()
        removeIdentityButton.configuration?.baseForegroundColor = .systemRed
        removeIdentityButton.configuration?.title = "Remove local node identity"
        removeIdentityButton.addTarget(
            self,
            action: #selector(confirmIdentityRemoval),
            for: .touchUpInside
        )
        removeIdentityButton.accessibilityHint = (
            "Shows the exact local node and asks for destructive confirmation "
                + "before deleting extension-owned credentials."
        )

        let stack = UIStackView(arrangedSubviews: [
            titleLabel,
            statusLabel,
            diagnosticLabel,
            originField,
            signInButton,
            startButton,
            stopButton,
            inspectButton,
            removeIdentityButton,
        ])
        stack.axis = .vertical
        stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        let scrollView = UIScrollView()
        scrollView.alwaysBounceVertical = true
        scrollView.keyboardDismissMode = .interactive
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollView)
        scrollView.addSubview(stack)
        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.topAnchor.constraint(
                equalTo: view.safeAreaLayoutGuide.topAnchor
            ),
            scrollView.bottomAnchor.constraint(
                equalTo: view.safeAreaLayoutGuide.bottomAnchor
            ),
            stack.leadingAnchor.constraint(
                equalTo: scrollView.contentLayoutGuide.leadingAnchor,
                constant: 24
            ),
            stack.trailingAnchor.constraint(
                equalTo: scrollView.contentLayoutGuide.trailingAnchor,
                constant: -24
            ),
            stack.topAnchor.constraint(
                equalTo: scrollView.contentLayoutGuide.topAnchor,
                constant: 24
            ),
            stack.bottomAnchor.constraint(
                equalTo: scrollView.contentLayoutGuide.bottomAnchor,
                constant: -24
            ),
            stack.widthAnchor.constraint(
                equalTo: scrollView.frameLayoutGuide.widthAnchor,
                constant: -48
            ),
        ])

        privacyShield.backgroundColor = .systemBackground
        privacyShield.isHidden = true
        privacyShield.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(privacyShield)
        NSLayoutConstraint.activate([
            privacyShield.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            privacyShield.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            privacyShield.topAnchor.constraint(equalTo: view.topAnchor),
            privacyShield.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(vpnStatusDidChange),
            name: .NEVPNStatusDidChange,
            object: nil
        )
        startInspection(clearsFailure: false)
    }

    deinit {
        inspectionTask?.cancel()
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func signInAndSetUpVPN() {
        guard setupTask == nil else {
            return
        }
        cancelInspection()
        setupFailureIsVisible = false
        backgroundCancelledSetup = false
        recordSetup(stage: .starting, result: "running")
        setControlsBusy(true)
        let rawOrigin = originField.text ?? ""
        setupTask = Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            let completed = await self.runAutomaticSetup(
                rawOrigin: rawOrigin
            )
            self.setupTask = nil
            self.setControlsBusy(false)
            if completed {
                self.startInspection(clearsFailure: false)
            }
        }
    }

    @MainActor
    private func runAutomaticSetup(rawOrigin: String) async -> Bool {
        var client: TunnelUserEnrollmentClient?
        var stage = TunnelAutomaticSetupStage.starting
        defer {
            isCompletingAuthorization = true
            authorizationSession?.cancel()
            authorizationSession = nil
            client?.invalidate()
            if enrollmentClient === client {
                enrollmentClient = nil
            }
        }
        do {
            try Task.checkCancellation()
            try requireNoLocalIdentity()
            let origin = try TunnelEnrollmentRequest.normalizedOrigin(
                rawOrigin
            )
            originField.text = origin
            originField.isEnabled = false
            statusLabel.text = (
                "Checking the Apple VPN configuration before sign-in. No "
                    + "enrollment token has been requested."
            )
            stage = .preparingManager
            recordSetup(stage: stage, result: "running")
            let preauthorizationManager =
                try await prepareManagerBeforeAuthorization(
                origin: origin
            )
            try Task.checkCancellation()
            preparedManager = preauthorizationManager
            preparedOrigin = origin

            statusLabel.text = (
                "The VPN configuration is ready. Opening \(origin) so you can "
                    + "sign in with your own account."
            )

            stage = .authorizing
            recordSetup(stage: stage, result: "running")
            let enrollmentClient = try TunnelUserEnrollmentClient(
                origin: origin
            )
            client = enrollmentClient
            self.enrollmentClient = enrollmentClient
            let authorization = try await enrollmentClient
                .startAuthorization()
            try Task.checkCancellation()
            let verificationURL = try authorization
                .validatedVerificationURL(serverOrigin: origin)
            try beginAuthorizationBrowser(url: verificationURL)
            _ = try await waitForAuthorization(
                authorization,
                client: enrollmentClient
            )
            try Task.checkCancellation()

            isCompletingAuthorization = true
            authorizationSession?.cancel()
            authorizationSession = nil
            statusLabel.text = (
                "Signed in. Reading the networks available to your account."
            )
            stage = .readingNetworks
            recordSetup(stage: stage, result: "running")
            let networks = try await enrollmentClient.networks()
            try Task.checkCancellation()
            let network = try await selectNetwork(networks)
            try Task.checkCancellation()

            stage = .verifyingManager
            recordSetup(stage: stage, result: "running")
            let currentManager =
                try await reloadReadyManagerAfterAuthorization(
                    expectedOrigin: origin
                )
            try Task.checkCancellation()
            preparedManager = currentManager
            try requireDisconnectedProvider(currentManager)
            statusLabel.text = (
                "Sign-in and VPN checks passed. Requesting a one-time enrollment "
                    + "for \(network.name)."
            )
            stage = .requestingEnrollment
            recordSetup(stage: stage, result: "running")
            let nodeName = try deviceEnrollmentNodeName()
            let enrollment = try await enrollmentClient.createSelfEnrollment(
                networkID: network.id,
                nodeName: nodeName
            )
            try Task.checkCancellation()
            stage = .handingOffEnrollment
            recordSetup(stage: stage, result: "running")
            try await handOffEnrollment(
                manager: currentManager,
                origin: origin,
                token: enrollment.enrollmentToken
            )
            inspectButton.isEnabled = true
            stopButton.isEnabled = true
            removeIdentityButton.isEnabled = true
            statusLabel.text = (
                "Signed in and installed the local tunnel identity. Apple reports "
                    + "the Packet Tunnel connected. The one-time token was never "
                    + "displayed or saved by the app. Runtime and packet status "
                    + "still require inspection."
            )
            recordSetup(stage: stage, result: "provider-connected")
            return true
        } catch {
            let result: String
            if backgroundCancelledSetup {
                result = "cancelled-background"
            } else if error is CancellationError {
                result = "cancelled"
            } else if case let TunnelHostError.providerStartFailed(code) =
                error
            {
                result = "failed-\(code)"
            } else if case TunnelHostError.providerStartTimedOut = error {
                result = "failed-provider-start-timeout"
            } else if case TunnelHostError.providerNotReady = error {
                result = "failed-provider-not-ready"
            } else if case TunnelHostError.providerConnectedWithoutIdentity =
                error
            {
                result = "failed-provider-connected-without-identity"
            } else {
                result = "failed"
            }
            recordSetup(stage: stage, result: result)
            statusLabel.text = setupFailureText(
                backgroundCancelledSetup ? CancellationError() : error,
                stage: stage
            )
            setupFailureIsVisible = true
            return false
        }
    }

    @MainActor
    private func beginAuthorizationBrowser(url: URL) throws {
        authorizationWasCancelled = false
        isCompletingAuthorization = false
        let session = ASWebAuthenticationSession(
            url: url,
            callbackURLScheme: nil
        ) { [weak self] _, error in
            Task { @MainActor [weak self] in
                guard let self else {
                    return
                }
                if error != nil && !self.isCompletingAuthorization {
                    self.authorizationWasCancelled = true
                }
                self.authorizationSession = nil
            }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        authorizationSession = session
        guard session.start() else {
            authorizationSession = nil
            throw TunnelUserEnrollmentError.authorizationUnavailable
        }
    }

    @MainActor
    private func waitForAuthorization(
        _ authorization: TunnelUserAuthorizationStartResponse,
        client: TunnelUserEnrollmentClient
    ) async throws -> TunnelUserAuthorizationCompletionResponse {
        let expiration = try authorization.expirationDate()
        var interval = authorization.intervalSeconds
        while Date() < expiration {
            try await Task.sleep(for: .seconds(interval))
            guard !authorizationWasCancelled else {
                throw TunnelUserEnrollmentError.authorizationCancelled
            }
            let completion = try await client.completeAuthorization(
                requestID: authorization.requestID,
                pollSecret: authorization.pollSecret
            )
            interval = completion.intervalSeconds
            switch completion.state {
            case .authorized:
                return completion
            case .pending:
                continue
            case .denied:
                throw TunnelUserEnrollmentError.authorizationDenied
            case .expired:
                throw TunnelUserEnrollmentError.authorizationExpired
            }
        }
        throw TunnelUserEnrollmentError.authorizationExpired
    }

    @MainActor
    private func selectNetwork(
        _ networks: [TunnelUserNetwork]
    ) async throws -> TunnelUserNetwork {
        guard !networks.isEmpty else {
            throw TunnelUserEnrollmentError.authorizationUnavailable
        }
        if networks.count == 1 {
            return networks[0]
        }
        guard networks.count <= 20 else {
            throw TunnelUserEnrollmentError.networkSelectionRequired
        }
        return try await withCheckedThrowingContinuation { continuation in
            let alert = UIAlertController(
                title: "Choose a Mesh network",
                message: "This device will join the selected network.",
                preferredStyle: .actionSheet
            )
            for network in networks {
                alert.addAction(
                    UIAlertAction(
                        title: network.name,
                        style: .default
                    ) { _ in
                        continuation.resume(returning: network)
                    }
                )
            }
            alert.addAction(
                UIAlertAction(title: "Cancel", style: .cancel) { _ in
                    continuation.resume(
                        throwing:
                            TunnelUserEnrollmentError.authorizationCancelled
                    )
                }
            )
            if let popover = alert.popoverPresentationController {
                popover.sourceView = self.signInButton
                popover.sourceRect = self.signInButton.bounds
            }
            present(alert, animated: true)
        }
    }

    private func handOffEnrollment(
        manager: NETunnelProviderManager,
        origin: String,
        token: String
    ) async throws {
        try requireDisconnectedProvider(manager)
        let request = try TunnelEnrollmentRequest(
            requestID: UUID().uuidString.lowercased(),
            serverOrigin: origin,
            enrollmentToken: token
        )
        let data = try request.encoded()
        guard let session = manager.connection
            as? NETunnelProviderSession
        else {
            throw TunnelHostError.providerSessionUnavailable
        }
        let previousConnectedAt = session.connectedDate
        providerStartObservationInProgress = true
        defer {
            providerStartObservationInProgress = false
        }
        try session.startTunnel(options: [
            TunnelEnrollmentRequest.startOptionKey: data as NSData,
        ])
        try await waitForProviderStart(
            session,
            requestID: request.requestID
        )
        let current = try loadLocalConfiguration()
        guard
            let connectedAt = session.connectedDate,
            TunnelProviderStartProof.accepts(
                finalStatus: providerObservedStatus(session.status),
                connectionDateChanged: connectedAt != previousConnectedAt,
                sameOriginIdentity: current?.controlPlaneOrigin == origin
            )
        else {
            throw TunnelHostError.providerConnectedWithoutIdentity
        }
    }

    private func waitForProviderStart(
        _ session: NETunnelProviderSession,
        requestID: String
    ) async throws {
        var observation = TunnelProviderStartObservation()
        let budget = TunnelProviderObservationBudget()
        let clock = ContinuousClock()
        let observationStartedAt = clock.now
        for _ in 1...Self.providerStartObservationAttempts {
            try Task.checkCancellation()
            guard budget.remaining(
                after: observationStartedAt.duration(to: clock.now)
            ) != nil else {
                throw TunnelHostError.providerStartTimedOut
            }
            let status = providerObservedStatus(session.status)
            switch observation.observe(status) {
            case .connected:
                return
            case .disconnectedAfterProgress:
                try await Task.sleep(for: .milliseconds(250))
                throw TunnelHostError.providerStartFailed(
                    await lastDisconnectCode(
                        session,
                        requestID: requestID
                    ) ?? "provider-start-failed"
                )
            case .invalid:
                throw TunnelHostError.providerStartFailed(
                    await lastDisconnectCode(
                        session,
                        requestID: requestID
                    ) ?? "apple-vpn-disconnected"
                )
            case .pending:
                break
            }
            guard let remaining = budget.remaining(
                after: observationStartedAt.duration(to: clock.now)
            ) else {
                throw TunnelHostError.providerStartTimedOut
            }
            try await Task.sleep(
                for: min(Self.providerStartObservationDelay, remaining)
            )
        }
        throw TunnelHostError.providerStartTimedOut
    }

    private func providerObservedStatus(
        _ status: NEVPNStatus
    ) -> TunnelProviderObservedStatus {
        switch status {
        case .disconnected:
            return .disconnected
        case .connecting:
            return .connecting
        case .connected:
            return .connected
        case .reasserting:
            return .reasserting
        case .disconnecting:
            return .disconnecting
        case .invalid:
            return .invalid
        @unknown default:
            return .invalid
        }
    }

    private func lastDisconnectCode(
        _ connection: NEVPNConnection,
        requestID: String
    ) async -> String? {
        let error: Error? = await withCheckedContinuation { continuation in
            let resolver = TunnelOneShotResult<Error?> { error in
                continuation.resume(returning: error)
            }
            connection.fetchLastDisconnectError { error in
                resolver.resolve(error)
            }
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + Self.disconnectErrorFetchTimeout
            ) {
                resolver.resolve(nil)
            }
        }
        guard let error else {
            return nil
        }
        let value = error as NSError
        return TunnelProviderFailureClassifier.classify(
            domain: value.domain,
            schema: value.userInfo[
                TunnelProviderFailureContract.schemaKey
            ] as? String,
            code: value.userInfo[
                TunnelProviderFailureContract.codeKey
            ] as? String,
            requestID: value.userInfo[
                TunnelProviderFailureContract.requestIDKey
            ] as? String,
            expectedRequestID: requestID,
            allowedCodes: Self.providerFailureCodes
        )
    }

    private func requireDisconnectedProvider(
        _ manager: NETunnelProviderManager
    ) throws {
        guard manager.connection.status == .disconnected else {
            throw TunnelHostError.providerNotReady
        }
    }

    @objc private func inspectConfiguration() {
        startInspection(clearsFailure: true)
    }

    private func startInspection(clearsFailure: Bool) {
        if clearsFailure {
            setupFailureIsVisible = false
        }
        inspectionGeneration += 1
        let generation = inspectionGeneration
        inspectionTask?.cancel()
        inspectionTask = Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            defer {
                if generation == self.inspectionGeneration {
                    self.inspectionTask = nil
                }
            }
            do {
                let managers = try await self.loadManagers()
                try self.requireCurrentInspection(generation)
                let matches = managers.filter { manager in
                    (manager.protocolConfiguration
                        as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier
                        == Self.providerBundleIdentifier
                }
                guard matches.count <= 1 else {
                    try self.requireCurrentInspection(generation)
                    self.disableRuntimeControls()
                    self.statusLabel.text = (
                        "Multiple Mesh Tunnel configurations exist. Runtime "
                            + "actions are disabled until the duplicate "
                            + "configuration is removed."
                    )
                    return
                }
                guard let manager = matches.first else {
                    try self.requireCurrentInspection(generation)
                    self.preparedManager = nil
                    self.preparedOrigin = nil
                    self.originField.isEnabled = true
                    self.signInButton.configuration?.title =
                        "Sign in and set up VPN"
                    self.signInButton.isEnabled = true
                    self.startButton.isEnabled = false
                    self.stopButton.isEnabled = false
                    self.removeIdentityButton.isEnabled = false
                    self.statusLabel.text = (
                        "No Mesh Tunnel VPN configuration is installed. "
                            + "Sign in to add one and enroll this device."
                    )
                    return
                }
                let origin = try self.validatedOrigin(
                    for: manager,
                    requireEnabled: false
                )
                let current = try self.loadLocalConfiguration()
                let status = try await self.configurationStatusText(
                    manager: manager,
                    current: current
                )
                try self.requireCurrentInspection(generation)
                self.preparedManager = manager
                self.preparedOrigin = origin
                self.originField.text = origin
                self.originField.isEnabled = false
                self.updateControls(
                    manager: manager,
                    hasLocalIdentity: current != nil
                )
                self.statusLabel.text = status
            } catch is CancellationError {
                return
            } catch {
                guard self.inspectionMayCommit(generation) else {
                    return
                }
                self.disableRuntimeControls()
                self.statusLabel.text = (
                    "Mesh Tunnel status is unavailable. No VPN configuration "
                        + "or local identity was changed."
                )
            }
        }
    }

    private func cancelInspection() {
        inspectionGeneration += 1
        inspectionTask?.cancel()
        inspectionTask = nil
    }

    private func inspectionMayCommit(_ generation: Int) -> Bool {
        generation == inspectionGeneration
            && setupTask == nil
            && !setupFailureIsVisible
    }

    private func requireCurrentInspection(_ generation: Int) throws {
        guard inspectionMayCommit(generation) else {
            throw CancellationError()
        }
    }

    @objc private func vpnStatusDidChange() {
        guard setupTask == nil, !setupFailureIsVisible else {
            return
        }
        startInspection(clearsFailure: false)
    }

    @objc private func startExistingTunnel() {
        guard setupTask == nil else {
            return
        }
        cancelInspection()
        guard preparedManager != nil, preparedOrigin != nil else {
            statusLabel.text = (
                "Inspect the installed Mesh Tunnel configuration before "
                    + "starting it."
            )
            return
        }
        setControlsBusy(true)
        setupTask = Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            await self.runStartExistingTunnel()
            self.setupTask = nil
        }
    }

    @MainActor
    private func runStartExistingTunnel() async {
        do {
            guard let manager = preparedManager,
                  let expectedOrigin = preparedOrigin,
                  let current = try loadLocalConfiguration(),
                  current.controlPlaneOrigin == expectedOrigin
            else {
                throw TunnelHostError.localIdentityUnavailable
            }
            try await enableManager(
                manager,
                expectedOrigin: expectedOrigin
            )
            guard let session = manager.connection
                as? NETunnelProviderSession,
                session.status == .disconnected
            else {
                throw TunnelHostError.providerSessionUnavailable
            }
            try session.startTunnel()
            inspectButton.isEnabled = true
            stopButton.isEnabled = true
            removeIdentityButton.isEnabled = true
            statusLabel.text = (
                "Tunnel start was requested for the authenticated local "
                    + "identity. Inspect runtime status before treating it as "
                    + "running or packet-capable."
            )
        } catch {
            setControlsBusy(false)
            statusLabel.text = (
                "The existing tunnel did not start. No local identity or VPN "
                    + "configuration was changed."
            )
        }
    }

    @objc private func stopTunnel() {
        guard let manager = preparedManager else {
            statusLabel.text = (
                "No inspected Mesh Tunnel configuration is available to stop."
            )
            return
        }
        manager.connection.stopVPNTunnel()
        startButton.isEnabled = false
        stopButton.isEnabled = false
        signInButton.isEnabled = false
        statusLabel.text = (
            "Tunnel stop was requested. Wait for the disconnected status "
                + "before changing or removing the local identity."
        )
    }

    @objc private func confirmIdentityRemoval() {
        do {
            guard let current = try loadLocalConfiguration() else {
                statusLabel.text = (
                    "No authenticated local Mesh node configuration is "
                        + "available to remove."
                )
                return
            }
            let alert = UIAlertController(
                title: "Remove local Mesh identity?",
                message: (
                    "Node \(current.nodeID) on network \(current.networkID) "
                        + "will stop. Its extension-only private key and agent "
                        + "credential will be deleted from this device. This "
                        + "does not revoke or delete the server-side node."
                ),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
            alert.addAction(
                UIAlertAction(
                    title: "Remove identity",
                    style: .destructive
                ) { [weak self] _ in
                    self?.beginIdentityRemoval(current: current)
                }
            )
            present(alert, animated: true)
        } catch {
            statusLabel.text = (
                "Local identity context could not be authenticated. Nothing "
                    + "was removed."
            )
        }
    }

    func protectForInactivity() {
        privacyShield.isHidden = false
    }

    func protectForBackground() {
        eraseTransientEnrollment()
        protectForInactivity()
    }

    func restoreFromBackground() {
        privacyShield.isHidden = true
    }

    @MainActor
    private func eraseTransientEnrollment() {
        authorizationWasCancelled = true
        isCompletingAuthorization = true
        authorizationSession?.cancel()
        authorizationSession = nil
        enrollmentClient?.invalidate()
        enrollmentClient = nil
        if providerStartObservationInProgress {
            recordSetup(
                stage: activeSetupStage,
                result: "provider-observation-backgrounded"
            )
            return
        }
        if setupTask != nil {
            backgroundCancelledSetup = true
            recordSetup(
                stage: activeSetupStage,
                result: "cancelled-background"
            )
        }
        setupTask?.cancel()
        if setupTask == nil {
            setControlsBusy(false)
        }
    }

    private func validatedOrigin(
        for manager: NETunnelProviderManager,
        requireEnabled: Bool = true
    ) throws -> String {
        guard (!requireEnabled || manager.isEnabled),
              !manager.isOnDemandEnabled,
              manager.onDemandRules == nil,
              let tunnelProtocol = manager.protocolConfiguration
                as? NETunnelProviderProtocol,
              tunnelProtocol.providerBundleIdentifier
                == Self.providerBundleIdentifier,
              let serverAddress = tunnelProtocol.serverAddress,
              try TunnelEnrollmentRequest.normalizedOrigin(serverAddress)
                == serverAddress,
              let configuration = tunnelProtocol.providerConfiguration,
              configuration.count == 1,
              configuration["schema"] as? String
                == TunnelEnrollmentRequest.schema
        else {
            throw TunnelHostError.savedConfigurationMismatch
        }
        return serverAddress
    }

    private func updateControls(
        manager: NETunnelProviderManager,
        hasLocalIdentity: Bool
    ) {
        inspectButton.isEnabled = true
        removeIdentityButton.isEnabled = hasLocalIdentity
        originField.isEnabled = false
        if !manager.isEnabled {
            signInButton.configuration?.title = hasLocalIdentity
                ? "Sign in and set up VPN"
                : "Replace VPN and sign in"
            startButton.isEnabled = hasLocalIdentity
            stopButton.isEnabled = false
            signInButton.isEnabled = !hasLocalIdentity
            return
        }
        signInButton.configuration?.title = "Sign in and set up VPN"
        switch manager.connection.status {
        case .disconnected:
            startButton.isEnabled = hasLocalIdentity
            stopButton.isEnabled = false
            signInButton.isEnabled = !hasLocalIdentity
        case .connecting, .connected, .reasserting:
            startButton.isEnabled = false
            stopButton.isEnabled = true
            signInButton.isEnabled = false
        case .disconnecting, .invalid:
            startButton.isEnabled = false
            stopButton.isEnabled = false
            signInButton.isEnabled = false
        @unknown default:
            disableRuntimeControls()
        }
    }

    private func disableRuntimeControls() {
        signInButton.isEnabled = false
        startButton.isEnabled = false
        stopButton.isEnabled = false
        removeIdentityButton.isEnabled = false
        inspectButton.isEnabled = true
    }

    private func configurationStatusText(
        manager: NETunnelProviderManager,
        current: TunnelConfigurationPayload?
    ) async throws -> String {
        if !manager.isEnabled {
            if current == nil {
                return (
                    "A saved Mesh Tunnel VPN configuration is disabled. "
                        + "Replace it before sign-in, then enroll this device. "
                        + "Mesh Tunnel will ask for confirmation and will not "
                        + "remove an enabled configuration or local identity."
                )
            } else {
                return (
                    "The saved Mesh Tunnel VPN configuration is disabled. "
                        + "Start the existing tunnel to restore it without "
                        + "creating another identity."
                )
            }
        }
        switch manager.connection.status {
        case .connected, .reasserting:
            guard let session = manager.connection
                as? NETunnelProviderSession
            else {
                throw TunnelHostError.providerSessionUnavailable
            }
            let request = TunnelControlRequest(
                requestID: UUID().uuidString.lowercased()
            )
            let response = try await sendProviderMessage(
                try request.encoded(),
                session: session
            )
            let outcome = try TunnelControlOutcome.decodeExact(response)
            guard outcome.requestID == request.requestID else {
                throw TunnelHostError.statusResponseMismatch
            }
            return try runtimeStatusText(
                outcome.evidence
            )
        case .connecting:
            return (
                "The Packet Tunnel is starting. Runtime and packet evidence "
                    + "is not available yet."
            )
        case .disconnecting:
            return (
                "The Packet Tunnel is stopping. Wait for the disconnected "
                    + "state before changing the local identity."
            )
        case .disconnected:
            if current == nil {
                return (
                    "The VPN configuration is prepared but no authenticated "
                        + "local identity is present. Sign in to enroll this "
                        + "device."
                )
            } else {
                return (
                    "An authenticated local identity is installed and the "
                        + "Packet Tunnel is stopped. No packet path is active."
                )
            }
        case .invalid:
            return (
                "The Mesh Tunnel VPN configuration is invalid. Runtime "
                    + "actions remain disabled."
            )
        @unknown default:
            throw TunnelHostError.providerSessionUnavailable
        }
    }

    private func runtimeStatusText(
        _ evidence: TunnelRuntimeEvidence
    ) throws -> String {
        switch evidence.state {
        case .running:
            guard let revision = evidence.configRevision,
                  let certificateGeneration =
                    evidence.certificateGeneration,
                  let packetsRead = evidence.packetsRead,
                  let packetsWritten = evidence.packetsWritten
            else {
                throw TunnelHostError.statusResponseMismatch
            }
            return (
                "The Packet Tunnel runtime reports running at configuration "
                    + "revision \(revision) and certificate generation "
                    + "\(certificateGeneration). Apple supplied "
                    + "\(packetsRead) packet"
                    + (packetsRead == 1 ? "" : "s")
                    + " to the engine; the engine returned "
                    + "\(packetsWritten) packet"
                    + (packetsWritten == 1 ? "" : "s")
                    + " to Apple. These counters do not by themselves prove "
                    + "a peer reply or end-to-end connectivity."
            )
        case .extensionError:
            guard let errorCode = evidence.errorCode else {
                throw TunnelHostError.statusResponseMismatch
            }
            return (
                "The Packet Tunnel reports extension error \(errorCode). No "
                    + "healthy or connected state is claimed."
            )
        default:
            return (
                "The Packet Tunnel runtime reports "
                    + "\(evidence.state.rawValue). No packet-path claim is "
                    + "made for this state."
            )
        }
    }

    private func setControlsBusy(_ busy: Bool) {
        removeIdentityButton.isEnabled = !busy
        if busy {
            signInButton.isEnabled = false
            startButton.isEnabled = false
            stopButton.isEnabled = false
            inspectButton.isEnabled = false
        } else if preparedManager == nil {
            signInButton.isEnabled = true
            originField.isEnabled = true
            inspectButton.isEnabled = true
            removeIdentityButton.isEnabled = false
        } else {
            updateControls(
                manager: preparedManager!,
                hasLocalIdentity: (try? loadLocalConfiguration()) != nil
            )
        }
    }

    private func beginIdentityRemoval(
        current: TunnelConfigurationPayload
    ) {
        setControlsBusy(true)
        Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            do {
                let managers = try await self.loadManagers()
                let matches = managers.filter { manager in
                    (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier
                        == Self.providerBundleIdentifier
                }
                guard matches.count == 1,
                      let manager = matches.first,
                      let session = manager.connection
                        as? NETunnelProviderSession
                else {
                    throw TunnelHostError.providerSessionUnavailable
                }
                let request = try TunnelIdentityRemovalRequest(
                    requestID: UUID().uuidString.lowercased(),
                    confirmationNodeID: current.nodeID
                )
                let encoded = try request.encoded()
                switch session.status {
                case .connected, .connecting, .reasserting:
                    let response = try await self.sendProviderMessage(
                        encoded,
                        session: session
                    )
                    let outcome = try TunnelIdentityRemovalOutcome.decodeExact(
                        response
                    )
                    guard outcome.requestID == request.requestID,
                          outcome.nodeID == current.nodeID
                    else {
                        throw TunnelHostError.identityRemovalMismatch
                    }
                case .disconnected, .disconnecting, .invalid:
                    try session.startTunnel(options: [
                        TunnelIdentityRemovalRequest.startOptionKey:
                            encoded as NSData,
                    ])
                    try await self.waitForLocalIdentityRemoval()
                @unknown default:
                    throw TunnelHostError.providerSessionUnavailable
                }
                try await self.remove(manager)
                self.preparedManager = nil
                self.preparedOrigin = nil
                self.originField.text = nil
                self.originField.isEnabled = true
                self.signInButton.isEnabled = true
                self.statusLabel.text = (
                    "Local identity \(current.nodeID) was removed and its VPN "
                        + "configuration was deleted. Server-side revocation or "
                        + "node deletion remains a separate administrator action."
                )
                self.setControlsBusy(false)
            } catch {
                self.statusLabel.text = (
                    "Local identity removal was not confirmed complete. The "
                        + "tunnel remains fail-closed; retry before transferring "
                        + "or re-enrolling this device."
                )
                self.setControlsBusy(false)
            }
        }
    }

    private func deviceEnrollmentNodeName() throws -> String {
        let key = "mesh.selfEnrollment.nodeName"
        if let existing = UserDefaults.standard.string(forKey: key),
           (try? TunnelUserSelfEnrollmentRequest(name: existing)) != nil
        {
            return existing
        }
        let suffix = UUID().uuidString
            .replacingOccurrences(of: "-", with: "")
            .lowercased()
            .prefix(12)
        let name = "ios-\(suffix)"
        _ = try TunnelUserSelfEnrollmentRequest(name: name)
        UserDefaults.standard.set(name, forKey: key)
        return name
    }

    private func setupFailureText(
        _ error: Error,
        stage: TunnelAutomaticSetupStage
    ) -> String {
        switch error {
        case _ as CancellationError:
            return (
                "Setup was cancelled and its temporary browser session was "
                    + "erased. No one-time token was retained."
            )
        case TunnelUserEnrollmentError.authorizationCancelled:
            return (
                "Sign-in was cancelled. No credential was displayed or "
                    + "stored by Mesh Tunnel."
            )
        case TunnelUserEnrollmentError.authorizationDenied:
            return "Your Mesh sign-in request was denied."
        case TunnelUserEnrollmentError.authorizationExpired:
            return "The sign-in request expired. Start again to retry."
        case TunnelUserEnrollmentError.networkSelectionRequired:
            return (
                "This account has too many available networks for this setup "
                    + "screen. Ask an administrator to narrow its access."
            )
        case TunnelHostError.localIdentityAlreadyInstalled:
            return (
                "This device already has an authenticated Mesh identity. "
                    + "Start the existing tunnel or remove that identity first."
            )
        case TunnelHostError.localIdentityStateUnavailable:
            return (
                "Mesh Tunnel could not prove that local identity storage is "
                    + "empty. No VPN configuration was replaced and no "
                    + "enrollment token was requested."
            )
        case TunnelHostError.staleManagerReplacementCancelled:
            return (
                "The disabled VPN configuration was not replaced. Sign-in was "
                    + "not opened and no enrollment token was requested."
            )
        case TunnelHostError.originMismatch:
            return (
                "The installed VPN configuration belongs to a different Mesh "
                    + "server. Remove it before switching servers."
            )
        case TunnelHostError.authenticationCookiesUnavailable,
             TunnelUserEnrollmentError.sessionStorageUnavailable:
            return (
                "Sign-in completed, but Mesh Tunnel could not retain the "
                    + "private authenticated app session. No enrollment token "
                    + "was requested."
            )
        case TunnelHostError.providerStartFailed(let code):
            return (
                "The Packet Tunnel stopped during enrollment at fixed stage "
                    + "\(code). The app did not retain the one-time token. "
                    + "Inspect the installed configuration before retrying."
            )
        case TunnelHostError.providerStartTimedOut:
            return (
                "The Packet Tunnel did not reach connected or a fixed failure "
                    + "stage within 90 seconds. Enrollment may still be running; "
                    + "inspect the installed configuration before retrying."
            )
        case TunnelHostError.providerNotReady:
            if stage == .handingOffEnrollment {
                return (
                    "Mesh issued a one-time enrollment, but the Apple VPN "
                        + "connection changed before dispatch. The app did not "
                        + "retain the token and did not start another provider."
                )
            }
            return (
                "The Apple VPN connection changed before enrollment could "
                    + "start. No new enrollment was requested while another "
                    + "provider transition may be active."
            )
        case TunnelHostError.providerConnectedWithoutIdentity:
            return (
                "Apple reported the Packet Tunnel connected, but Mesh could "
                    + "not verify the new local identity for this server. No "
                    + "working tunnel is claimed."
            )
        case TunnelHostError.httpStatus(let status):
            return stage.httpFailureText(status: status)
        default:
            return stage.failureText
        }
    }

    private func recordSetup(
        stage: TunnelAutomaticSetupStage,
        result: String
    ) {
        activeSetupStage = stage
        UserDefaults.standard.set(
            stage.rawValue,
            forKey: Self.lastSetupStageKey
        )
        UserDefaults.standard.set(
            result,
            forKey: Self.lastSetupResultKey
        )
        updateDiagnosticLabel()
    }

    private func updateDiagnosticLabel() {
        let shortVersion =
            Bundle.main.object(
                forInfoDictionaryKey: "CFBundleShortVersionString"
            ) as? String ?? "unknown"
        let build =
            Bundle.main.object(
                forInfoDictionaryKey: "CFBundleVersion"
            ) as? String ?? "unknown"
        let stage = UserDefaults.standard.string(
            forKey: Self.lastSetupStageKey
        ) ?? "not-run"
        let result = UserDefaults.standard.string(
            forKey: Self.lastSetupResultKey
        ) ?? "not-run"
        diagnosticLabel.text = (
            "Build \(shortVersion) (\(build)) · Last setup: "
                + "\(result)-\(stage)"
        )
    }

    private func loadLocalConfiguration()
        throws -> TunnelConfigurationPayload?
    {
        guard
            let container = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier:
                    "group.io.rw0.mesh.tunnel.mobile"
            ),
            let key = try TunnelHandoffKeychain.loadExisting()
        else {
            return nil
        }
        let store = try TunnelConfigurationStore(
            containerURL: container,
            key: key,
            highWater: TunnelHostInspectionHighWater()
        )
        return try store.readCurrent()
    }

    private func requireNoLocalIdentity() throws {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier:
                "group.io.rw0.mesh.tunnel.mobile"
        ) else {
            throw TunnelHostError.localIdentityStateUnavailable
        }
        for slot in [
            TunnelConfigurationStore.currentSlot,
            TunnelConfigurationStore.candidateSlot,
            TunnelConfigurationStore.recoverySlot,
        ] where FileManager.default.fileExists(
            atPath: container.appendingPathComponent(slot).path
        ) {
            throw TunnelHostError.localIdentityAlreadyInstalled
        }
        guard try loadLocalConfiguration() == nil else {
            throw TunnelHostError.localIdentityAlreadyInstalled
        }
    }

    private func sendProviderMessage(
        _ data: Data,
        session: NETunnelProviderSession
    ) async throws -> Data {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            do {
                try session.sendProviderMessage(data) { response in
                    guard let response else {
                        continuation.resume(
                            throwing: TunnelHostError.identityRemovalMismatch
                        )
                        return
                    }
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func waitForLocalIdentityRemoval() async throws {
        for _ in 0..<30 {
            try await Task.sleep(for: .milliseconds(500))
            if try loadLocalConfiguration() == nil {
                return
            }
        }
        throw TunnelHostError.identityRemovalTimeout
    }

    @MainActor
    private func prepareManagerBeforeAuthorization(
        origin: String
    ) async throws -> NETunnelProviderManager {
        let managers = try await loadManagers()
        let matches = managers.filter { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier
                == Self.providerBundleIdentifier
        }
        guard matches.count <= 1 else {
            throw TunnelHostError.ambiguousManager
        }
        if let manager = matches.first {
            try await reload(manager)
            guard try validatedOrigin(
                for: manager,
                requireEnabled: false
            ) == origin else {
                throw TunnelHostError.originMismatch
            }
            guard !manager.isEnabled else {
                return manager
            }
            try requireNoLocalIdentity()
            guard await confirmStaleManagerReplacement(origin: origin) else {
                throw TunnelHostError.staleManagerReplacementCancelled
            }
            return try await replaceStaleManager(
                manager,
                expectedOrigin: origin
            )
        }
        return try await createManager(origin: origin)
    }

    private func reloadReadyManagerAfterAuthorization(
        expectedOrigin: String
    ) async throws -> NETunnelProviderManager {
        for attempt in
            1...Self.postAuthorizationManagerReadinessAttempts
        {
            do {
                return try await loadReadyManagerAfterAuthorization(
                    expectedOrigin: expectedOrigin
                )
            } catch TunnelHostError.managerNotReady {
                guard attempt
                    < Self.postAuthorizationManagerReadinessAttempts
                else {
                    throw TunnelHostError.managerNotReady
                }
                try await Task.sleep(
                    for: Self.postAuthorizationManagerReadinessDelay
                )
            }
        }
        throw TunnelHostError.managerNotReady
    }

    private func loadReadyManagerAfterAuthorization(
        expectedOrigin: String
    ) async throws -> NETunnelProviderManager {
        let managers = try await loadManagers()
        let matches = managers.filter { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier
                == Self.providerBundleIdentifier
        }
        guard matches.count <= 1 else {
            throw TunnelHostError.ambiguousManager
        }
        guard let currentManager = matches.first else {
            throw TunnelHostError.managerNotReady
        }
        try await reload(currentManager)
        try requireNoLocalIdentity()
        guard try validatedOrigin(
            for: currentManager,
            requireEnabled: false
        ) == expectedOrigin else {
            throw TunnelHostError.originMismatch
        }
        guard currentManager.isEnabled else {
            throw TunnelHostError.managerNotReady
        }
        return currentManager
    }

    @MainActor
    private func confirmStaleManagerReplacement(
        origin: String
    ) async -> Bool {
        await withCheckedContinuation { continuation in
            let alert = UIAlertController(
                title: "Replace disabled VPN configuration?",
                message: (
                    "iOS retained one disabled Mesh Tunnel configuration for "
                        + "\(origin), but this app has no local Mesh identity. "
                        + "Replace only that saved VPN configuration before "
                        + "sign-in? This does not delete a server-side node."
                ),
                preferredStyle: .alert
            )
            alert.addAction(
                UIAlertAction(title: "Cancel", style: .cancel) { _ in
                    continuation.resume(returning: false)
                }
            )
            alert.addAction(
                UIAlertAction(
                    title: "Replace VPN configuration",
                    style: .destructive
                ) { _ in
                    continuation.resume(returning: true)
                }
            )
            present(alert, animated: true)
        }
    }

    private func replaceStaleManager(
        _ expectedManager: NETunnelProviderManager,
        expectedOrigin: String
    ) async throws -> NETunnelProviderManager {
        try requireNoLocalIdentity()
        let managers = try await loadManagers()
        let matches = managers.filter { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier
                == Self.providerBundleIdentifier
        }
        guard matches.count == 1,
              let currentManager = matches.first
        else {
            throw TunnelHostError.ambiguousManager
        }
        try await reload(expectedManager)
        try await reload(currentManager)
        try requireNoLocalIdentity()
        guard !expectedManager.isEnabled,
              !currentManager.isEnabled,
              try validatedOrigin(
                for: expectedManager,
                requireEnabled: false
              ) == expectedOrigin,
              try validatedOrigin(
                for: currentManager,
                requireEnabled: false
              ) == expectedOrigin
        else {
            throw TunnelHostError.savedConfigurationMismatch
        }
        try await remove(currentManager)
        let remaining = (try await loadManagers()).filter { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier
                == Self.providerBundleIdentifier
        }
        guard remaining.isEmpty else {
            throw TunnelHostError.ambiguousManager
        }
        return try await createManager(origin: expectedOrigin)
    }

    private func createManager(
        origin: String
    ) async throws -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier =
            Self.providerBundleIdentifier
        tunnelProtocol.serverAddress = origin
        tunnelProtocol.providerConfiguration = [
            "schema": TunnelEnrollmentRequest.schema,
        ]
        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "Mesh Tunnel"
        manager.isEnabled = true
        manager.isOnDemandEnabled = false
        manager.onDemandRules = nil
        try await save(manager)
        try await reload(manager)
        guard manager.isEnabled,
              let saved = manager.protocolConfiguration
                as? NETunnelProviderProtocol,
              saved.providerBundleIdentifier
                == Self.providerBundleIdentifier,
              saved.serverAddress == origin,
              (saved.providerConfiguration?["schema"] as? String)
                == TunnelEnrollmentRequest.schema
        else {
            throw TunnelHostError.savedConfigurationMismatch
        }
        return manager
    }

    private func enableManager(
        _ manager: NETunnelProviderManager,
        expectedOrigin: String
    ) async throws {
        try await reload(manager)
        guard try validatedOrigin(
            for: manager,
            requireEnabled: false
        ) == expectedOrigin else {
            throw TunnelHostError.originMismatch
        }
        manager.isEnabled = true
        try await save(manager)
        try await reload(manager)
        guard try validatedOrigin(for: manager) == expectedOrigin else {
            throw TunnelHostError.savedConfigurationMismatch
        }
    }

    private func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func reload(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func remove(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            manager.removeFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}

extension MeshTunnelViewController:
    ASWebAuthenticationPresentationContextProviding
{
    func presentationAnchor(
        for _: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        view.window ?? ASPresentationAnchor()
    }
}

private final class TunnelUserEnrollmentClient {
    private let origin: String
    private let cookieStorage: HTTPCookieStorage
    private let session: URLSession
    private var invalidated = false

    init(origin: String) throws {
        self.origin = try TunnelEnrollmentRequest.normalizedOrigin(origin)
        guard URL(string: self.origin) != nil else {
            throw TunnelHostError.invalidServerResponse
        }
        let configuration = try TunnelUserEnrollmentSessionFactory
            .ephemeralConfiguration()
        guard let privateCookieStorage = configuration.httpCookieStorage else {
            throw TunnelUserEnrollmentError.sessionStorageUnavailable
        }
        cookieStorage = privateCookieStorage
        session = URLSession(configuration: configuration)
    }

    func invalidate() {
        guard !invalidated else {
            return
        }
        invalidated = true
        for cookie in cookieStorage.cookies ?? [] {
            cookieStorage.deleteCookie(cookie)
        }
        session.invalidateAndCancel()
    }

    func startAuthorization() async throws
        -> TunnelUserAuthorizationStartResponse
    {
        let data = try await send(
            path: "/api/v1/auth/desktop/start",
            method: "POST",
            body: Data("{}".utf8),
            expectedStatus: 201,
            requiresCSRF: false
        )
        return try TunnelUserAuthorizationStartResponse.decode(
            data,
            serverOrigin: origin
        )
    }

    func completeAuthorization(
        requestID: String,
        pollSecret: String
    ) async throws -> TunnelUserAuthorizationCompletionResponse {
        let body = try JSONSerialization.data(
            withJSONObject: [
                "request_id": requestID,
                "poll_secret": pollSecret,
            ],
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let data = try await send(
            path: "/api/v1/auth/desktop/complete",
            method: "POST",
            body: body,
            expectedStatus: 200,
            requiresCSRF: false
        )
        let completion =
            try TunnelUserAuthorizationCompletionResponse.decode(data)
        if completion.state == .authorized {
            _ = try csrfToken(
                for: try endpoint(path: "/api/v1/networks")
            )
        }
        return completion
    }

    func networks() async throws -> [TunnelUserNetwork] {
        let data = try await send(
            path: "/api/v1/networks",
            method: "GET",
            body: nil,
            expectedStatus: 200,
            requiresCSRF: false
        )
        return try TunnelUserNetwork.decodeList(data)
    }

    func createSelfEnrollment(
        networkID: String,
        nodeName: String
    ) async throws -> TunnelUserSelfEnrollmentResponse {
        let request = try TunnelUserSelfEnrollmentRequest(name: nodeName)
        let data = try await send(
            path: "/api/v1/networks/\(networkID)/self-enrollment",
            method: "POST",
            body: try request.encoded(),
            expectedStatus: 201,
            requiresCSRF: true
        )
        return try TunnelUserSelfEnrollmentResponse.decode(
            data,
            networkID: networkID,
            nodeName: nodeName
        )
    }

    private func send(
        path: String,
        method: String,
        body: Data?,
        expectedStatus: Int,
        requiresCSRF: Bool
    ) async throws -> Data {
        let url = try endpoint(path: path)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil {
            request.setValue(
                "application/json",
                forHTTPHeaderField: "Content-Type"
            )
            request.setValue(origin, forHTTPHeaderField: "Origin")
        }
        if requiresCSRF {
            request.setValue(
                try csrfToken(for: url),
                forHTTPHeaderField: "X-Mesh-CSRF"
            )
        }
        let (data, response) = try await session.data(for: request)
        guard data.count <= 4 * 1024 * 1024,
              let httpResponse = response as? HTTPURLResponse
        else {
            throw TunnelHostError.invalidServerResponse
        }
        guard httpResponse.statusCode == expectedStatus else {
            throw TunnelHostError.httpStatus(httpResponse.statusCode)
        }
        return data
    }

    private func endpoint(path: String) throws -> URL {
        guard path.hasPrefix("/"),
              let url = URL(string: origin + path)
        else {
            throw TunnelHostError.invalidServerResponse
        }
        return url
    }

    private func csrfToken(for url: URL) throws -> String {
        let cookies = cookieStorage.cookies(for: url) ?? []
        let sessions = cookies.filter {
            $0.name == "mesh_session"
                || $0.name == "__Host-mesh_session"
        }
        let csrfCookies = cookies.filter {
            $0.name == "mesh_csrf"
                || $0.name == "__Host-mesh_csrf"
        }
        guard sessions.count == 1,
              !sessions[0].value.isEmpty,
              csrfCookies.count == 1,
              !csrfCookies[0].value.isEmpty,
              sessions[0].value != csrfCookies[0].value
        else {
            throw TunnelHostError.authenticationCookiesUnavailable
        }
        return csrfCookies[0].value
    }
}

private struct TunnelHostInspectionHighWater: TunnelHighWaterStore {
    func load() throws -> UInt64 {
        0
    }

    func commit(_: UInt64) throws {
        throw TunnelKeychainError.rollbackOrReplay
    }
}

private enum TunnelHostError: Error {
    case ambiguousManager
    case originMismatch
    case providerSessionUnavailable
    case savedConfigurationMismatch
    case localIdentityUnavailable
    case statusResponseMismatch
    case identityRemovalMismatch
    case identityRemovalTimeout
    case localIdentityAlreadyInstalled
    case localIdentityStateUnavailable
    case staleManagerReplacementCancelled
    case managerNotReady
    case authenticationCookiesUnavailable
    case providerStartFailed(String)
    case providerStartTimedOut
    case providerNotReady
    case providerConnectedWithoutIdentity
    case invalidServerResponse
    case httpStatus(Int)
}

private enum TunnelAutomaticSetupStage: String {
    case starting
    case authorizing
    case readingNetworks
    case preparingManager
    case verifyingManager
    case requestingEnrollment
    case handingOffEnrollment

    var failureText: String {
        switch self {
        case .starting, .authorizing:
            return (
                "Sign-in setup did not finish. No one-time enrollment token "
                    + "was requested or retained."
            )
        case .readingNetworks:
            return (
                "Sign-in succeeded, but Mesh Tunnel could not read the "
                    + "networks available to this account. No enrollment token "
                    + "was requested."
            )
        case .preparingManager:
            return (
                "Apple did not make the VPN configuration ready. Sign-in was "
                    + "not opened and no enrollment token was requested."
            )
        case .verifyingManager:
            return (
                "Sign-in succeeded, but iOS did not return the ready VPN "
                    + "configuration after a bounded recheck. No enrollment "
                    + "token was requested."
            )
        case .requestingEnrollment:
            return (
                "The VPN configuration is ready, but Mesh did not issue a "
                    + "one-time enrollment. No token was retained."
            )
        case .handingOffEnrollment:
            return (
                "Mesh issued a one-time enrollment, but the Packet Tunnel "
                    + "extension did not accept the handoff. Retry to replace "
                    + "the still-pending enrollment safely."
            )
        }
    }

    func httpFailureText(status: Int) -> String {
        switch self {
        case .starting, .authorizing:
            return (
                "The Mesh server rejected the sign-in exchange (HTTP "
                    + "\(status)). No enrollment token was requested."
            )
        case .readingNetworks:
            return (
                "Sign-in completed, but the Mesh server rejected the "
                    + "authenticated network read (HTTP \(status)). No "
                    + "enrollment token was requested."
            )
        case .requestingEnrollment:
            return (
                "The Mesh server rejected self-enrollment (HTTP \(status)). "
                    + "No one-time token was retained."
            )
        case .preparingManager, .verifyingManager, .handingOffEnrollment:
            return failureText
        }
    }
}
