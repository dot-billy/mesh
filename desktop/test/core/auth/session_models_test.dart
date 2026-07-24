import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/auth/rbac.dart';
import 'package:mesh_desktop/core/auth/session_models.dart';

void main() {
  test('parses the current exact session and RBAC contract', () {
    final session = SessionContext.fromJson(<String, Object?>{
      'authenticated': true,
      'session_id': 'session_123',
      'principal': <String, Object?>{
        'id': 'oidc_principal_123',
        'kind': 'oidc_admin',
        'issuer': 'https://id.example',
        'subject': 'operator-1',
        'display_name': 'Mesh Operator',
        'email': 'operator@example.com',
        'groups': <Object?>['mesh-operators'],
        'acr': 'urn:mfa',
        'amr': <Object?>['mfa', 'pwd'],
        'auth_time': '2026-07-23T12:00:00Z',
      },
      'auth_method': 'oidc',
      'role': 'operator',
      'permissions': <Object?>['networks.read', 'networks.write', 'audit.read'],
      'created_at': '2026-07-23T12:00:00Z',
      'last_seen_at': '2026-07-23T12:01:00Z',
      'idle_expires_at': '2026-07-23T12:31:00Z',
      'absolute_expires_at': '2026-07-23T20:00:00Z',
    });

    expect(session.role, MeshRole.operator);
    expect(session.principal.label, 'Mesh Operator');
    expect(session.permissions.canReadNetworks, isTrue);
    expect(session.permissions.canChangeNetworks, isTrue);
    expect(session.permissions.canPerformSecurityActions, isFalse);
    expect(session.permissions.canManageIdentity, isFalse);
    expect(session.permissions.canReadAudit, isTrue);
    expect(
      session.isExpiredAt(DateTime.parse('2026-07-23T12:20:00Z')),
      isFalse,
    );
    expect(session.isExpiredAt(DateTime.parse('2026-07-23T12:31:00Z')), isTrue);
  });

  test('rejects unknown or duplicate permissions and response drift', () {
    Map<String, Object?> document(Object permissions) => <String, Object?>{
      'authenticated': true,
      'principal': <String, Object?>{
        'id': 'legacy_admin',
        'kind': 'legacy_admin',
        'auth_time': '2026-07-23T12:00:00Z',
      },
      'auth_method': 'legacy_bearer',
      'role': 'admin',
      'permissions': permissions,
    };

    expect(
      () => SessionContext.fromJson(
        document(<Object?>['networks.read', 'future.permission']),
      ),
      throwsFormatException,
    );
    expect(
      () => SessionContext.fromJson(
        document(<Object?>['networks.read', 'networks.read']),
      ),
      throwsFormatException,
    );
    expect(
      () => SessionContext.fromJson(<String, Object?>{
        ...document(<Object?>['networks.read']),
        'unexpected': true,
      }),
      throwsFormatException,
    );
  });

  test('RBAC helpers use explicit server-returned permissions', () {
    final viewerWithWriteHint = <MeshPermission>{
      MeshPermission.networksRead,
      MeshPermission.networksWrite,
    };

    expect(viewerWithWriteHint.canChangeNetworks, isTrue);
    expect(viewerWithWriteHint.canPerformSecurityActions, isFalse);
    expect(MeshRole.parse('viewer'), MeshRole.viewer);
    expect(() => MeshRole.parse('owner'), throwsFormatException);
  });
}
