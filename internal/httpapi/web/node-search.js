(function publishMeshNodeSearch(root, factory) {
  const search = factory();
  if (typeof module === 'object' && module.exports) module.exports = search;
  if (root) root.MeshNodeSearch = search;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshNodeSearch() {
  'use strict';

  const MAX_QUERY_LENGTH = 256;

  function normalize(value) {
    return String(value ?? '').normalize('NFKC').toLocaleLowerCase().trim();
  }

  function queryTokens(query) {
    if (typeof query !== 'string' || query.length > MAX_QUERY_LENGTH || /[\u0000-\u001f\u007f]/u.test(query)) {
      throw new Error('Invalid node search query');
    }
    return [...new Set(normalize(query).split(/\s+/u).filter(Boolean))];
  }

  function searchableValues(node) {
    if (!node || typeof node !== 'object' || Array.isArray(node)) throw new Error('Invalid searchable node');
    const values = [
      node.id, node.name, node.ip, node.role, node.site, node.failure_domain,
      node.status, node.lifecycleStatus, node.phase, node.severity,
      node.operational ? 'online operational healthy' : '',
      node.nebula_running ? 'nebula running' : '',
    ];
    if (Array.isArray(node.groups)) values.push(...node.groups);
    if (Array.isArray(node.routed_subnets)) values.push(...node.routed_subnets);
    if (Array.isArray(node.alerts)) {
      for (const alert of node.alerts) {
        if (alert && typeof alert === 'object' && !Array.isArray(alert)) {
          values.push(alert.code, alert.kind, alert.severity, alert.message);
        }
      }
    }
    return normalize(values.filter((value) => typeof value === 'string').join(' '));
  }

  function matches(node, query) {
    const tokens = queryTokens(query);
    if (tokens.length === 0) return true;
    const text = searchableValues(node);
    return tokens.every((token) => text.includes(token));
  }

  function filter(nodes, query) {
    if (!Array.isArray(nodes)) throw new Error('Invalid node inventory');
    const tokens = queryTokens(query);
    if (tokens.length === 0) return nodes.slice();
    return nodes.filter((node) => {
      const text = searchableValues(node);
      return tokens.every((token) => text.includes(token));
    });
  }

  return Object.freeze({ MAX_QUERY_LENGTH, normalize, queryTokens, searchableValues, matches, filter });
}));
