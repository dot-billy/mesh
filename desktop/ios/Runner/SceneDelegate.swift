import Flutter
import UIKit

class SceneDelegate: FlutterSceneDelegate {
  private let privacyShield = PrivacyShieldController()

  override func sceneWillResignActive(_ scene: UIScene) {
    privacyShield.cover(window)
    super.sceneWillResignActive(scene)
  }

  override func sceneDidEnterBackground(_ scene: UIScene) {
    privacyShield.cover(window)
    super.sceneDidEnterBackground(scene)
  }

  override func sceneDidBecomeActive(_ scene: UIScene) {
    super.sceneDidBecomeActive(scene)
    privacyShield.reveal()
  }

  override func sceneDidDisconnect(_ scene: UIScene) {
    privacyShield.cover(window)
    super.sceneDidDisconnect(scene)
  }
}

final class PrivacyShieldController {
  private weak var protectedWindow: UIWindow?
  private var shield: UIView?

  var isCovering: Bool {
    shield?.superview != nil
  }

  func cover(_ window: UIWindow?) {
    guard let window else {
      return
    }
    if isCovering {
      return
    }

    let shield = UIView(frame: window.bounds)
    shield.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    shield.backgroundColor = .systemBackground
    shield.accessibilityViewIsModal = true
    shield.accessibilityLabel = "Mesh Admin content hidden"

    let mark = UILabel()
    mark.translatesAutoresizingMaskIntoConstraints = false
    mark.text = "Mesh Admin"
    mark.font = .preferredFont(forTextStyle: .title1)
    mark.adjustsFontForContentSizeCategory = true
    mark.textColor = .label
    mark.isAccessibilityElement = true
    mark.accessibilityLabel = "Mesh Admin locked"
    shield.addSubview(mark)
    NSLayoutConstraint.activate([
      mark.centerXAnchor.constraint(equalTo: shield.centerXAnchor),
      mark.centerYAnchor.constraint(equalTo: shield.centerYAnchor),
    ])

    window.addSubview(shield)
    protectedWindow = window
    self.shield = shield
    MeshAdminLog.record(.privacyShieldCovered)
  }

  func reveal() {
    let wasCovering = isCovering
    shield?.removeFromSuperview()
    shield = nil
    protectedWindow = nil
    if wasCovering {
      MeshAdminLog.record(.privacyShieldRevealed)
    }
  }
}
