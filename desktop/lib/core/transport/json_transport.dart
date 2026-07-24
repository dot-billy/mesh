import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/legacy_admin_bearer.dart';
import 'package:mesh_desktop/core/transport/mesh_cookie_jar.dart';

final class JsonApiResponse {
  const JsonApiResponse({
    required this.statusCode,
    required this.body,
    this.retryAfter,
  });

  final int statusCode;
  final Object? body;

  /// A validated delta-seconds `Retry-After` hint.
  ///
  /// Arbitrary response headers are deliberately not exposed. Values outside
  /// the safe one-second to one-hour range are ignored.
  final Duration? retryAfter;

  bool get isSuccess => statusCode >= 200 && statusCode < 300;
}

abstract interface class JsonTransport {
  Future<JsonApiResponse> send({
    required String method,
    required String path,
    Map<String, String>? queryParameters,
    Object? body,
    bool hasBody = false,
    bool authenticated = true,
    bool sameOriginJson = false,
  });
}

final class DartIoJsonTransport implements JsonTransport {
  DartIoJsonTransport({
    required this.profile,
    HttpClient? client,
    MeshCookieJar? cookieJar,
    LegacyAdministratorBearerProvider? legacyBearerProvider,
    this.maximumResponseBytes = 8 << 20,
    this.responseTimeout = const Duration(seconds: 30),
  }) : _client = client ?? HttpClient(),
       _ownsClient = client == null,
       cookieJar = cookieJar ?? MeshCookieJar(profile),
       _legacyBearerProvider = legacyBearerProvider ?? _noLegacyBearer {
    if (maximumResponseBytes < 1) {
      throw ArgumentError.value(
        maximumResponseBytes,
        'maximumResponseBytes',
        'must be positive',
      );
    }
    _client
      ..autoUncompress = false
      ..connectionTimeout = const Duration(seconds: 10);
  }

  final ConnectionProfile profile;
  final MeshCookieJar cookieJar;
  final int maximumResponseBytes;
  final Duration responseTimeout;
  final HttpClient _client;
  final bool _ownsClient;
  final LegacyAdministratorBearerProvider _legacyBearerProvider;

  static Future<LegacyAdministratorBearer?> _noLegacyBearer() async => null;

  @override
  Future<JsonApiResponse> send({
    required String method,
    required String path,
    Map<String, String>? queryParameters,
    Object? body,
    bool hasBody = false,
    bool authenticated = true,
    bool sameOriginJson = false,
  }) async {
    final normalizedMethod = method.toUpperCase();
    if (method != normalizedMethod || !_methods.contains(normalizedMethod)) {
      throw const ApiProtocolException('Unsupported HTTP method.');
    }
    if ((normalizedMethod == 'GET' || normalizedMethod == 'HEAD') && hasBody) {
      throw const ApiProtocolException(
        'GET and HEAD requests cannot contain a body.',
      );
    }
    if (sameOriginJson &&
        (!hasBody || !_unsafeMethods.contains(normalizedMethod))) {
      throw const ApiProtocolException(
        'Same-origin authentication requests must be unsafe JSON requests.',
      );
    }
    final endpoint = profile.endpoint(path, queryParameters: queryParameters);
    final legacyBearer = authenticated ? await _legacyBearerProvider() : null;
    if (legacyBearer != null && cookieJar.hasSession) {
      throw const ApiProtocolException(
        'Refusing an ambiguous cookie and authorization credential request.',
      );
    }
    final csrf =
        legacyBearer == null &&
            authenticated &&
            _unsafeMethods.contains(normalizedMethod) &&
            cookieJar.hasSession
        ? cookieJar.csrfToken
        : null;
    if (legacyBearer == null &&
        authenticated &&
        _unsafeMethods.contains(normalizedMethod) &&
        cookieJar.hasSession &&
        csrf == null) {
      throw const ApiProtocolException(
        'Cookie-authenticated mutation is missing its CSRF credential.',
      );
    }
    final request = await _client.openUrl(normalizedMethod, endpoint);
    request
      ..followRedirects = false
      ..maxRedirects = 0;
    request.headers
      ..set(HttpHeaders.acceptHeader, 'application/json')
      ..set(HttpHeaders.cacheControlHeader, 'no-store');
    if (sameOriginJson) {
      request.headers.set('Origin', profile.originString);
    }

    if (legacyBearer != null) {
      request.headers.set(
        HttpHeaders.authorizationHeader,
        legacyBearer.headerValue,
      );
    } else if (authenticated) {
      cookieJar.applyTo(request);
      if (_unsafeMethods.contains(normalizedMethod) && cookieJar.hasSession) {
        request.headers
          ..set('X-Mesh-CSRF', csrf!)
          ..set('Origin', profile.originString);
      }
    }

    if (hasBody) {
      final encoded = utf8.encode(jsonEncode(body));
      request.headers
        ..set(HttpHeaders.contentTypeHeader, 'application/json')
        ..contentLength = encoded.length;
      request.add(encoded);
    } else {
      request.contentLength = 0;
    }

    final response = await request.close().timeout(responseTimeout);
    if (response.isRedirect) {
      await response.drain<void>();
      throw const ApiProtocolException('API redirects are not accepted.');
    }
    final retryAfter = _parseRetryAfter(response.headers);
    cookieJar.capture(response.cookies);
    final bytes = await _readBounded(response);
    if (normalizedMethod == 'HEAD' ||
        response.statusCode == HttpStatus.noContent) {
      if (bytes.isNotEmpty) {
        throw const ApiProtocolException(
          'Bodyless API response contained bytes.',
        );
      }
      return JsonApiResponse(
        statusCode: response.statusCode,
        body: null,
        retryAfter: retryAfter,
      );
    }
    if (bytes.isEmpty) {
      throw const ApiProtocolException('JSON API response was empty.');
    }
    _requireJsonContentType(response.headers);
    final text = utf8.decode(bytes, allowMalformed: false);
    Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException {
      throw const ApiProtocolException(
        'API response did not contain one valid JSON value.',
      );
    }
    return JsonApiResponse(
      statusCode: response.statusCode,
      body: decoded,
      retryAfter: retryAfter,
    );
  }

  Duration? _parseRetryAfter(HttpHeaders headers) {
    final values = headers[HttpHeaders.retryAfterHeader];
    if (values == null || values.length != 1) {
      return null;
    }
    final value = values.single;
    if (!_deltaSeconds.hasMatch(value)) {
      return null;
    }
    final seconds = int.tryParse(value);
    if (seconds == null || seconds < 1 || seconds > 3600) {
      return null;
    }
    return Duration(seconds: seconds);
  }

  Future<Uint8List> _readBounded(HttpClientResponse response) async {
    final encodings = response.headers[HttpHeaders.contentEncodingHeader];
    if (encodings != null &&
        (encodings.length != 1 ||
            encodings.single.toLowerCase() != 'identity')) {
      await response.drain<void>();
      throw const ApiProtocolException(
        'Encoded API responses are not accepted.',
      );
    }
    final signedLength = response.contentLength;
    if (signedLength > maximumResponseBytes) {
      await response.drain<void>();
      throw const ApiProtocolException('API response exceeded its size limit.');
    }
    final bytes = BytesBuilder(copy: false);
    var length = 0;
    try {
      await for (final chunk in response.timeout(responseTimeout)) {
        length += chunk.length;
        if (length > maximumResponseBytes) {
          throw const ApiProtocolException(
            'API response exceeded its size limit.',
          );
        }
        bytes.add(chunk);
      }
    } on TimeoutException {
      throw const ApiProtocolException('API response timed out.');
    }
    return bytes.takeBytes();
  }

  void _requireJsonContentType(HttpHeaders headers) {
    final values = headers[HttpHeaders.contentTypeHeader];
    if (values == null || values.length != 1) {
      throw const ApiProtocolException(
        'API response must have one JSON content type.',
      );
    }
    ContentType contentType;
    try {
      contentType = ContentType.parse(values.single);
    } on FormatException {
      throw const ApiProtocolException('API response content type is invalid.');
    }
    if (contentType.mimeType.toLowerCase() != 'application/json' ||
        contentType.charset != null &&
            contentType.charset!.toLowerCase() != 'utf-8') {
      throw const ApiProtocolException(
        'API response content type is not JSON.',
      );
    }
  }

  void close({bool force = false}) {
    if (_ownsClient) {
      _client.close(force: force);
    }
  }

  static const Set<String> _methods = <String>{
    'GET',
    'HEAD',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
  };
  static const Set<String> _unsafeMethods = <String>{
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
  };
  static final RegExp _deltaSeconds = RegExp(r'^[0-9]+$');
}

final class ApiProtocolException implements Exception {
  const ApiProtocolException(this.message);

  final String message;

  @override
  String toString() => 'ApiProtocolException: $message';
}
