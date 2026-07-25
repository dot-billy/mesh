import 'package:mesh_desktop/core/auth/rbac.dart';

enum PrincipalKind {
  oidcAdmin('oidc_admin'),
  legacyAdmin('legacy_admin'),
  serviceAccount('service_account'),
  breakGlass('break_glass');

  const PrincipalKind(this.wireValue);

  final String wireValue;

  static PrincipalKind parse(Object? value) {
    if (value is! String) {
      throw const FormatException('Principal kind must be a string.');
    }
    return values.firstWhere(
      (kind) => kind.wireValue == value,
      orElse: () =>
          throw FormatException('Unsupported principal kind "$value".'),
    );
  }
}

final class MeshPrincipal {
  MeshPrincipal({
    required this.id,
    required this.kind,
    required this.authTime,
    this.issuer,
    this.subject,
    this.displayName,
    this.email,
    List<String> groups = const <String>[],
    this.acr,
    List<String> amr = const <String>[],
  }) : groups = List<String>.unmodifiable(groups),
       amr = List<String>.unmodifiable(amr) {
    if (!_identifier.hasMatch(id)) {
      throw const FormatException('Principal ID is invalid.');
    }
  }

  factory MeshPrincipal.fromJson(Object? value) {
    final object = _exactObject(
      value,
      required: const <String>{'id', 'kind', 'auth_time'},
      optional: const <String>{
        'issuer',
        'subject',
        'display_name',
        'email',
        'groups',
        'acr',
        'amr',
      },
      name: 'principal',
    );
    return MeshPrincipal(
      id: _requiredString(object, 'id'),
      kind: PrincipalKind.parse(object['kind']),
      authTime: _requiredTime(object, 'auth_time'),
      issuer: _optionalString(object, 'issuer'),
      subject: _optionalString(object, 'subject'),
      displayName: _optionalString(object, 'display_name'),
      email: _optionalString(object, 'email'),
      groups: _stringList(object['groups'], 'principal groups'),
      acr: _optionalString(object, 'acr'),
      amr: _stringList(object['amr'], 'principal AMR'),
    );
  }

  static final RegExp _identifier = RegExp(r'^[A-Za-z0-9_-]{1,128}$');

  final String id;
  final PrincipalKind kind;
  final DateTime authTime;
  final String? issuer;
  final String? subject;
  final String? displayName;
  final String? email;
  final List<String> groups;
  final String? acr;
  final List<String> amr;

  String get label {
    final display = displayName;
    if (display != null && display.isNotEmpty) {
      return display;
    }
    final address = email;
    if (address != null && address.isNotEmpty) {
      return address;
    }
    return id;
  }
}

final class SessionContext {
  SessionContext({
    required this.sessionId,
    required this.principal,
    required this.authMethod,
    required this.role,
    required Set<MeshPermission> permissions,
    this.createdAt,
    this.lastSeenAt,
    this.idleExpiresAt,
    this.absoluteExpiresAt,
  }) : permissions = Set<MeshPermission>.unmodifiable(permissions) {
    if (sessionId != null && !_identifier.hasMatch(sessionId!)) {
      throw const FormatException('Session ID is invalid.');
    }
    if (authMethod.isEmpty || authMethod.length > 64) {
      throw const FormatException('Authentication method is invalid.');
    }
  }

  factory SessionContext.fromJson(Object? value) {
    final object = _exactObject(
      value,
      required: const <String>{
        'authenticated',
        'principal',
        'auth_method',
        'role',
        'permissions',
      },
      optional: const <String>{
        'session_id',
        'created_at',
        'last_seen_at',
        'idle_expires_at',
        'absolute_expires_at',
      },
      name: 'session',
    );
    if (object['authenticated'] != true) {
      throw const FormatException('Session is not authenticated.');
    }
    final rawPermissions = object['permissions'];
    if (rawPermissions is! List<Object?>) {
      throw const FormatException('Session permissions must be an array.');
    }
    final permissions = <MeshPermission>{};
    for (final value in rawPermissions) {
      if (!permissions.add(MeshPermission.parse(value))) {
        throw const FormatException('Session contains duplicate permissions.');
      }
    }
    return SessionContext(
      sessionId: _optionalString(object, 'session_id'),
      principal: MeshPrincipal.fromJson(object['principal']),
      authMethod: _requiredString(object, 'auth_method'),
      role: MeshRole.parse(object['role']),
      permissions: permissions,
      createdAt: _optionalTime(object, 'created_at'),
      lastSeenAt: _optionalTime(object, 'last_seen_at'),
      idleExpiresAt: _optionalTime(object, 'idle_expires_at'),
      absoluteExpiresAt: _optionalTime(object, 'absolute_expires_at'),
    );
  }

  static final RegExp _identifier = RegExp(r'^[A-Za-z0-9_-]{1,128}$');

  final String? sessionId;
  final MeshPrincipal principal;
  final String authMethod;
  final MeshRole role;
  final Set<MeshPermission> permissions;
  final DateTime? createdAt;
  final DateTime? lastSeenAt;
  final DateTime? idleExpiresAt;
  final DateTime? absoluteExpiresAt;

  bool allows(MeshPermission permission) => permissions.allows(permission);

  bool isExpiredAt(DateTime now) {
    final absolute = absoluteExpiresAt;
    final idle = idleExpiresAt;
    return absolute != null && !now.isBefore(absolute) ||
        idle != null && !now.isBefore(idle);
  }
}

sealed class AuthenticationState {
  const AuthenticationState();
}

final class SignedOut extends AuthenticationState {
  const SignedOut();
}

final class Authenticating extends AuthenticationState {
  const Authenticating();
}

final class Authenticated extends AuthenticationState {
  const Authenticated(this.session);

  final SessionContext session;
}

final class AuthenticationFailed extends AuthenticationState {
  const AuthenticationFailed(this.message);

  final String message;
}

Map<String, Object?> _exactObject(
  Object? value, {
  required Set<String> required,
  required Set<String> optional,
  required String name,
}) {
  if (value is! Map<String, Object?>) {
    throw FormatException('$name must be a JSON object.');
  }
  for (final field in required) {
    if (!value.containsKey(field)) {
      throw FormatException('$name is missing "$field".');
    }
  }
  for (final field in value.keys) {
    if (!required.contains(field) && !optional.contains(field)) {
      throw FormatException('$name contains unsupported field "$field".');
    }
  }
  return value;
}

String _requiredString(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! String || value.isEmpty) {
    throw FormatException('"$field" must be a nonempty string.');
  }
  return value;
}

String? _optionalString(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value == null) {
    return null;
  }
  if (value is! String || value.isEmpty) {
    throw FormatException('"$field" must be a nonempty string when present.');
  }
  return value;
}

DateTime _requiredTime(Map<String, Object?> object, String field) {
  final value = _requiredString(object, field);
  final parsed = DateTime.tryParse(value);
  if (parsed == null || !parsed.isUtc || !value.endsWith('Z')) {
    throw FormatException('"$field" must be a UTC timestamp.');
  }
  return parsed;
}

DateTime? _optionalTime(Map<String, Object?> object, String field) {
  if (object[field] == null) {
    return null;
  }
  return _requiredTime(object, field);
}

List<String> _stringList(Object? value, String name) {
  if (value == null) {
    return const <String>[];
  }
  if (value is! List<Object?>) {
    throw FormatException('$name must be an array.');
  }
  final result = <String>[];
  final seen = <String>{};
  for (final item in value) {
    if (item is! String || item.isEmpty || !seen.add(item)) {
      throw FormatException('$name contains an invalid or duplicate value.');
    }
    result.add(item);
  }
  return result;
}
