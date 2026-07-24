import 'package:flutter/material.dart';

import '../models/presentation_models.dart';

class PermissionGate extends StatelessWidget {
  const PermissionGate({
    required this.role,
    required this.permission,
    required this.child,
    this.readOnlyChild,
    super.key,
  });

  final MeshRole role;
  final MeshPermission permission;
  final Widget child;
  final Widget? readOnlyChild;

  @override
  Widget build(BuildContext context) {
    if (role.allows(permission)) return child;
    if (readOnlyChild != null) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          readOnlyChild!,
          const SizedBox(height: 12),
          _PermissionNotice(role: role, permission: permission),
        ],
      );
    }
    return _PermissionNotice(role: role, permission: permission);
  }
}

class _PermissionNotice extends StatelessWidget {
  const _PermissionNotice({required this.role, required this.permission});

  final MeshRole role;
  final MeshPermission permission;

  @override
  Widget build(BuildContext context) {
    final requiredRole = switch (permission) {
      MeshPermission.networksRead || MeshPermission.auditRead => 'Viewer',
      MeshPermission.networksWrite => 'Operator',
      MeshPermission.networksSecurity ||
      MeshPermission.identityManage => 'Admin',
    };
    final message =
        '$requiredRole permission required. Current role: ${role.label}.';
    return Semantics(
      label: message,
      container: true,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerHigh,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              const Icon(Icons.lock_outline, size: 18),
              const SizedBox(width: 10),
              Expanded(child: Text(message)),
            ],
          ),
        ),
      ),
    );
  }
}
