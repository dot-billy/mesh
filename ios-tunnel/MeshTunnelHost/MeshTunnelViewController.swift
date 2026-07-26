import AuthenticationServices
import NetworkExtension
import UIKit

final class MeshTunnelViewController: UIViewController {
    private static let providerBundleIdentifier =
        "io.rw0.mesh.tunnel.mobile.packet-tunnel"

    private let statusLabel = UILabel()
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
    private var setupTask: Task<Void, Never>?
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
        inspectConfiguration()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func signInAndSetUpVPN() {
        guard setupTask == nil else {
            return
        }
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
            if completed {
                self.inspectConfiguration()
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
            guard try loadLocalConfiguration() == nil else {
                throw TunnelHostError.localIdentityAlreadyInstalled
            }
            let origin = try TunnelEnrollmentRequest.normalizedOrigin(
                rawOrigin
            )
            originField.text = origin
            originField.isEnabled = false
            statusLabel.text = (
                "Opening \(origin) so you can sign in with your own account."
            )

            let enrollmentClient = try TunnelUserEnrollmentClient(
                origin: origin
            )
            client = enrollmentClient
            self.enrollmentClient = enrollmentClient
            stage = .authorizing
            let authorization = try await enrollmentClient
                .startAuthorization()
            let verificationURL = try authorization
                .validatedVerificationURL(serverOrigin: origin)
            try beginAuthorizationBrowser(url: verificationURL)
            _ = try await waitForAuthorization(
                authorization,
                client: enrollmentClient
            )

            isCompletingAuthorization = true
            authorizationSession?.cancel()
            authorizationSession = nil
            statusLabel.text = (
                "Signed in. Reading the networks available to your account."
            )
            stage = .readingNetworks
            let networks = try await enrollmentClient.networks()
            let network = try await selectNetwork(networks)

            statusLabel.text = (
                "Allow Mesh Tunnel to add the Apple VPN configuration when "
                    + "iOS asks. No enrollment token has been created yet."
            )
            stage = .preparingManager
            let manager = try await prepareManager(origin: origin)
            preparedManager = manager
            preparedOrigin = origin

            statusLabel.text = (
                "VPN configuration added. Requesting a one-time enrollment "
                    + "for \(network.name)."
            )
            stage = .requestingEnrollment
            let nodeName = try deviceEnrollmentNodeName()
            let enrollment = try await enrollmentClient.createSelfEnrollment(
                networkID: network.id,
                nodeName: nodeName
            )
            stage = .handingOffEnrollment
            try handOffEnrollment(
                manager: manager,
                origin: origin,
                token: enrollment.enrollmentToken
            )
            inspectButton.isEnabled = true
            stopButton.isEnabled = true
            removeIdentityButton.isEnabled = true
            statusLabel.text = (
                "Signed in and handed enrollment to the Packet Tunnel "
                    + "extension. The one-time token was never displayed or "
                    + "saved by the app. Runtime status must still be verified "
                    + "before treating the tunnel as connected."
            )
            return true
        } catch {
            setControlsBusy(false)
            statusLabel.text = setupFailureText(error, stage: stage)
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
    ) throws {
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
        try session.startTunnel(options: [
            TunnelEnrollmentRequest.startOptionKey: data as NSData,
        ])
    }

    @objc private func inspectConfiguration() {
        Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            do {
                let managers = try await self.loadManagers()
                let matches = managers.filter { manager in
                    (manager.protocolConfiguration
                        as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier
                        == Self.providerBundleIdentifier
                }
                guard matches.count <= 1 else {
                    self.disableRuntimeControls()
                    self.statusLabel.text = (
                        "Multiple Mesh Tunnel configurations exist. Runtime "
                            + "actions are disabled until the duplicate "
                            + "configuration is removed."
                    )
                    return
                }
                guard let manager = matches.first else {
                    self.preparedManager = nil
                    self.preparedOrigin = nil
                    self.originField.isEnabled = true
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
                self.preparedManager = manager
                self.preparedOrigin = origin
                self.originField.text = origin
                self.originField.isEnabled = false
                let current = try self.loadLocalConfiguration()
                self.updateControls(
                    manager: manager,
                    hasLocalIdentity: current != nil
                )
                try await self.presentRuntimeStatus(manager: manager)
            } catch {
                self.disableRuntimeControls()
                self.statusLabel.text = (
                    "Mesh Tunnel status is unavailable. No VPN configuration "
                        + "or local identity was changed."
                )
            }
        }
    }

    @objc private func vpnStatusDidChange() {
        guard setupTask == nil else {
            return
        }
        inspectConfiguration()
    }

    @objc private func startExistingTunnel() {
        guard setupTask == nil else {
            return
        }
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
        setupTask?.cancel()
        setControlsBusy(false)
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
            startButton.isEnabled = hasLocalIdentity
            stopButton.isEnabled = false
            signInButton.isEnabled = !hasLocalIdentity
            return
        }
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

    private func presentRuntimeStatus(
        manager: NETunnelProviderManager
    ) async throws {
        let current = try loadLocalConfiguration()
        if !manager.isEnabled {
            if current == nil {
                statusLabel.text = (
                    "A saved Mesh Tunnel VPN configuration is disabled. "
                        + "Sign in to restore it and enroll this device."
                )
            } else {
                statusLabel.text = (
                    "The saved Mesh Tunnel VPN configuration is disabled. "
                        + "Start the existing tunnel to restore it without "
                        + "creating another identity."
                )
            }
            return
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
            statusLabel.text = try runtimeStatusText(
                outcome.evidence
            )
        case .connecting:
            statusLabel.text = (
                "The Packet Tunnel is starting. Runtime and packet evidence "
                    + "is not available yet."
            )
        case .disconnecting:
            statusLabel.text = (
                "The Packet Tunnel is stopping. Wait for the disconnected "
                    + "state before changing the local identity."
            )
        case .disconnected:
            if current == nil {
                statusLabel.text = (
                    "The VPN configuration is prepared but no authenticated "
                        + "local identity is present. Sign in to enroll this "
                        + "device."
                )
            } else {
                statusLabel.text = (
                    "An authenticated local identity is installed and the "
                        + "Packet Tunnel is stopped. No packet path is active."
                )
            }
        case .invalid:
            statusLabel.text = (
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
        case TunnelHostError.originMismatch:
            return (
                "The installed VPN configuration belongs to a different Mesh "
                    + "server. Remove it before switching servers."
            )
        case TunnelHostError.httpStatus(let status):
            return (
                "The Mesh server rejected setup (HTTP \(status)). Confirm "
                    + "that self-service enrollment is enabled for your account."
            )
        default:
            return stage.failureText
        }
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

    private func prepareManager(
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
            if !manager.isEnabled {
                try await enableManager(
                    manager,
                    expectedOrigin: origin
                )
            }
            return manager
        }
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
    private let baseURL: URL
    private let cookieStorage: HTTPCookieStorage
    private let session: URLSession
    private var invalidated = false

    init(origin: String) throws {
        self.origin = try TunnelEnrollmentRequest.normalizedOrigin(origin)
        guard let baseURL = URL(string: self.origin) else {
            throw TunnelHostError.invalidServerResponse
        }
        self.baseURL = baseURL
        cookieStorage = HTTPCookieStorage()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .always
        configuration.httpCookieStorage = cookieStorage
        configuration.httpShouldSetCookies = true
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
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
        return try TunnelUserAuthorizationCompletionResponse.decode(data)
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
        guard path.hasPrefix("/"),
              let url = URL(string: origin + path)
        else {
            throw TunnelHostError.invalidServerResponse
        }
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
            let cookies = cookieStorage.cookies(for: baseURL) ?? []
            guard cookies.contains(where: {
                $0.name == "mesh_session"
                    || $0.name == "__Host-mesh_session"
            }),
            let csrf = cookies.filter({
                $0.name == "mesh_csrf" || $0.name == "__Host-mesh_csrf"
            }).only,
            !csrf.value.isEmpty
            else {
                throw TunnelHostError.authenticationCookiesUnavailable
            }
            request.setValue(csrf.value, forHTTPHeaderField: "X-Mesh-CSRF")
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
}

private extension Collection {
    var only: Element? {
        count == 1 ? first : nil
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
    case authenticationCookiesUnavailable
    case invalidServerResponse
    case httpStatus(Int)
}

private enum TunnelAutomaticSetupStage {
    case starting
    case authorizing
    case readingNetworks
    case preparingManager
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
                "Sign-in succeeded, but Apple did not make the VPN "
                    + "configuration ready. No enrollment token was requested."
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
}
