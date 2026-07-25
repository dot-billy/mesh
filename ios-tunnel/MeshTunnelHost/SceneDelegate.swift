import UIKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else {
            return
        }
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = MeshTunnelViewController()
        window.makeKeyAndVisible()
        self.window = window
    }

    func sceneWillResignActive(_ scene: UIScene) {
        (window?.rootViewController as? MeshTunnelViewController)?
            .protectForBackground()
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        (window?.rootViewController as? MeshTunnelViewController)?
            .protectForBackground()
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        (window?.rootViewController as? MeshTunnelViewController)?
            .restoreFromBackground()
    }
}
