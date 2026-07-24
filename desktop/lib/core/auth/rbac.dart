enum MeshRole {
  viewer('viewer'),
  operator('operator'),
  admin('admin');

  const MeshRole(this.wireValue);

  final String wireValue;

  static MeshRole parse(Object? value) {
    if (value is! String) {
      throw const FormatException('RBAC role must be a string.');
    }
    return values.firstWhere(
      (role) => role.wireValue == value,
      orElse: () => throw FormatException('Unsupported RBAC role "$value".'),
    );
  }
}

enum MeshPermission {
  networksRead('networks.read'),
  networksWrite('networks.write'),
  networksSecurity('networks.security'),
  identityManage('identity.manage'),
  auditRead('audit.read');

  const MeshPermission(this.wireValue);

  final String wireValue;

  static MeshPermission parse(Object? value) {
    if (value is! String) {
      throw const FormatException('RBAC permission must be a string.');
    }
    return values.firstWhere(
      (permission) => permission.wireValue == value,
      orElse: () =>
          throw FormatException('Unsupported RBAC permission "$value".'),
    );
  }
}

/// Presentation-only access helpers.
///
/// The server remains the authorization authority. These helpers control
/// affordances in the desktop UI and must never be treated as an enforcement
/// boundary.
extension MeshPermissionSet on Set<MeshPermission> {
  bool allows(MeshPermission permission) => contains(permission);

  bool get canReadNetworks => allows(MeshPermission.networksRead);
  bool get canChangeNetworks => allows(MeshPermission.networksWrite);
  bool get canPerformSecurityActions => allows(MeshPermission.networksSecurity);
  bool get canManageIdentity => allows(MeshPermission.identityManage);
  bool get canReadAudit => allows(MeshPermission.auditRead);
}
