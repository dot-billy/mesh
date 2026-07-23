# Durable release-origin generation publication

**Status:** Implementation target.

## Problem

`mesh-origin` already verifies a canonical index and every indexed object, but
the deployment contract accepts repository and index paths independently. The
operator documentation asks for an atomic generation switch without defining
the generation layout, publication barriers, selection rule, or rollback
evidence. A mismatched pair fails startup, but it is still an avoidable
operational failure during a release.

## Trust boundary

An origin generation is an availability and deployment object, not release
authority. Its index SHA-256 binds paths, sizes, content types, cache policies,
and object digests, but neither that index nor its generation receipt replaces
the independently authenticated bootstrap-handoff digest or threshold-signed
release metadata.

Generation authoring is Linux-only because publication requires an atomic
same-directory `renameat2(RENAME_NOREPLACE)`. Serving remains the existing
read-only Linux container contract.

## Layout and identity

One generation lives at:

```text
GENERATIONS_ROOT/<64-lowercase-index-sha256>/
  generation.json
  origin-index.json
  repository/<only paths named by origin-index.json>
```

The canonical `mesh-release-origin-generation-v1` receipt records the
generation/index SHA-256, object count, and exact total indexed bytes. The
directory name must equal that digest. The receipt is operational evidence,
not a signing record.

All files are single-link regular files with mode `0444`; all generation
directories have mode `0555`. No symlink or unindexed file is allowed anywhere
inside the generation.

## Publication

`mesh-release publish-origin-generation` accepts a clean absolute source root,
canonical stable-read index, and an existing operator-controlled generations
root. It:

1. authenticates canonical index structure;
2. stable-opens each explicitly indexed source object;
3. copies through an exact size and SHA-256 check without following links;
4. writes the exact index and canonical receipt with no replacement;
5. fsyncs every file and directory;
6. reopens and validates the complete staged generation through the production
   origin store;
7. removes write permissions; and
8. publishes with no-replace rename followed by a generations-root fsync.

Normal failure removes only its exact hidden staging directory. Crash residue
remains hidden and cannot be selected as a generation; operators inspect it
before removal.

`mesh-release inspect-origin-generation` repeats the exact receipt, tree,
mode, digest, and production-store validation without mutation.

## Deployment and rollback

Compose accepts one `MESH_ORIGIN_GENERATION` path and derives both read-only
mounts from it. A rollout first inspects the candidate, starts a separate
instance or staging hostname, and verifies every required object. Deployment
then selects that exact generation directory and recreates the container.
Rollback selects a previously retained and freshly inspected generation; it
never rewrites a channel file or combines an old repository with a new index.

Retention deletion is deliberately outside this command. A generation may be
needed for installer rollback, audit, or incident response, so removal requires
an explicit external retention policy and deployment-reference check.

## Proof

Unit tests require deterministic identity and receipt bytes, source-mutation
isolation, exact-tree enforcement, no replacement, wrong digest rejection, and
linked-path rejection. The native-TLS origin smoke publishes a generation,
serves only that generation, requires inspection, proves a second publication
cannot replace it, and makes an in-place mutation of the selected generation
fail readiness and retrieval closed before exact cleanup.
