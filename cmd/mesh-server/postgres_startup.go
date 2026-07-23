package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"mesh/internal/control"
	"mesh/internal/identity"
	"mesh/internal/postgresstore"
)

type postgresDocumentReader interface {
	ReadPair(context.Context) (postgresstore.Document, postgresstore.Document, error)
}

type postgresImportReadiness interface {
	postgresDocumentReader
	CheckImportReadiness(context.Context) error
}

type contextReadinessChecker interface {
	CheckReadiness(context.Context) error
}

type recoveryBindingChecker interface {
	CheckCurrentRecoveryCredentialBinding(masterVerifier, adminVerifier string) error
}

type postgresRecoveryDocuments struct {
	control  postgresstore.Document
	identity postgresstore.Document
}

func readPostgresRecoveryDocuments(ctx context.Context, reader postgresDocumentReader) (postgresRecoveryDocuments, error) {
	if ctx == nil {
		return postgresRecoveryDocuments{}, errors.New("PostgreSQL recovery read requires a context")
	}
	if reader == nil {
		return postgresRecoveryDocuments{}, errors.New("PostgreSQL recovery reader is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return postgresRecoveryDocuments{}, err
	}
	controlDocument, identityDocument, err := reader.ReadPair(ctx)
	if err != nil {
		clear(controlDocument.Bytes)
		clear(identityDocument.Bytes)
		return postgresRecoveryDocuments{}, fmt.Errorf("read PostgreSQL recovery document pair: %w", err)
	}
	documents := postgresRecoveryDocuments{control: controlDocument, identity: identityDocument}
	if err := validatePostgresRecoveryDocument(controlDocument, postgresstore.DomainControl, postgresstore.MaxControlDocumentBytes); err != nil {
		clearPostgresRecoveryDocuments(&documents)
		return postgresRecoveryDocuments{}, errors.New("PostgreSQL control recovery document metadata is invalid")
	}
	if err := ctx.Err(); err != nil {
		clearPostgresRecoveryDocuments(&documents)
		return postgresRecoveryDocuments{}, err
	}
	if err := validatePostgresRecoveryDocument(identityDocument, postgresstore.DomainIdentity, postgresstore.MaxIdentityDocumentBytes); err != nil {
		clearPostgresRecoveryDocuments(&documents)
		return postgresRecoveryDocuments{}, errors.New("PostgreSQL identity recovery document metadata is invalid")
	}
	if err := ctx.Err(); err != nil {
		clearPostgresRecoveryDocuments(&documents)
		return postgresRecoveryDocuments{}, err
	}
	return documents, nil
}

func validatePostgresRecoveryDocument(document postgresstore.Document, expected postgresstore.Domain, maxBytes int) error {
	if document.Domain != expected || document.Revision < 1 || len(document.Bytes) == 0 || len(document.Bytes) > maxBytes {
		return errors.New("invalid document metadata")
	}
	digest := sha256.Sum256(document.Bytes)
	if subtle.ConstantTimeCompare(digest[:], document.SHA256[:]) != 1 {
		return errors.New("document checksum mismatch")
	}
	return nil
}

func clearPostgresRecoveryDocuments(documents *postgresRecoveryDocuments) {
	if documents == nil {
		return
	}
	clear(documents.control.Bytes)
	clear(documents.identity.Bytes)
	*documents = postgresRecoveryDocuments{}
}

// validatePostgresRecoveryDocuments is deliberately independent of the live
// adapters. Startup uses it on the exact authoritative bytes before any
// compatibility update can run. When requireConfiguredCredential is false,
// the control snapshot is still fully decrypted and validated; this is the
// pre-mutation path used only for an explicitly authorized administrator-token
// rotation. The configured token is then required after the rotation commits.
func validatePostgresRecoveryDocuments(documents postgresRecoveryDocuments, box *control.SecretBox, masterKey, adminToken []byte, requireConfiguredCredential bool) error {
	if requireConfiguredCredential {
		if err := control.ValidateRecoverySnapshotCredentials(documents.control.Bytes, masterKey, adminToken); err != nil {
			return fmt.Errorf("authenticate PostgreSQL control recovery document: %w", err)
		}
	} else if err := control.ValidateRecoverySnapshot(documents.control.Bytes, box); err != nil {
		return fmt.Errorf("validate PostgreSQL control recovery document: %w", err)
	}
	if err := identity.ValidateRecoverySnapshot(documents.identity.Bytes, box); err != nil {
		return fmt.Errorf("validate PostgreSQL identity recovery document: %w", err)
	}
	return nil
}

func validatePostgresStartupRecovery(ctx context.Context, reader postgresDocumentReader, box *control.SecretBox, masterKey []byte, adminToken string, requireConfiguredCredential bool) error {
	documents, err := readPostgresRecoveryDocuments(ctx, reader)
	if err != nil {
		return err
	}
	defer clearPostgresRecoveryDocuments(&documents)
	adminBytes := []byte(adminToken)
	defer clear(adminBytes)
	return validatePostgresRecoveryDocuments(documents, box, masterKey, adminBytes, requireConfiguredCredential)
}

type postgresRecoveryVersion struct {
	revision int64
	sha256   [32]byte
}

// postgresRecoveryValidator reruns recovery-grade cryptographic checks only
// when an authoritative document revision/hash changes. Reads still happen on
// every readiness probe so database checksum validation and change detection
// cannot be bypassed by a stale in-process cache.
type postgresRecoveryValidator struct {
	mu       sync.Mutex
	reader   postgresDocumentReader
	box      *control.SecretBox
	control  postgresRecoveryVersion
	identity postgresRecoveryVersion
	ready    bool
}

func (validator *postgresRecoveryValidator) Check(ctx context.Context) error {
	if validator == nil || validator.reader == nil || validator.box == nil {
		return errors.New("PostgreSQL recovery validator is unavailable")
	}
	validator.mu.Lock()
	defer validator.mu.Unlock()
	documents, err := readPostgresRecoveryDocuments(ctx, validator.reader)
	if err != nil {
		return err
	}
	defer clearPostgresRecoveryDocuments(&documents)
	controlVersion := postgresRecoveryVersion{revision: documents.control.Revision, sha256: documents.control.SHA256}
	identityVersion := postgresRecoveryVersion{revision: documents.identity.Revision, sha256: documents.identity.SHA256}
	if !validator.ready || validator.control != controlVersion {
		if err := control.ValidateRecoverySnapshot(documents.control.Bytes, validator.box); err != nil {
			return fmt.Errorf("validate live PostgreSQL control recovery document: %w", err)
		}
	}
	if !validator.ready || validator.identity != identityVersion {
		if err := identity.ValidateRecoverySnapshot(documents.identity.Bytes, validator.box); err != nil {
			return fmt.Errorf("validate live PostgreSQL identity recovery document: %w", err)
		}
	}
	validator.control = controlVersion
	validator.identity = identityVersion
	validator.ready = true
	return nil
}

func postgresRuntimeReadinessCheck(
	store postgresImportReadiness,
	controlStore contextReadinessChecker,
	identityStore contextReadinessChecker,
	service recoveryBindingChecker,
	recovery *postgresRecoveryValidator,
	masterVerifier, adminVerifier string,
) func(context.Context) error {
	// This composes deliberately independent proofs. With the current exact-
	// document API, provenance, both adapters, the binding check, and recovery
	// change detection each perform authoritative reads. Correctness takes
	// priority here; a future revision-only probe can collapse the redundant
	// byte transfers without weakening these gates.
	return func(ctx context.Context) error {
		if ctx == nil {
			return errors.New("runtime readiness context is unavailable")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if store == nil || controlStore == nil || identityStore == nil || service == nil || recovery == nil {
			return errors.New("runtime dependency is unavailable")
		}
		if err := store.CheckImportReadiness(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := controlStore.CheckReadiness(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := identityStore.CheckReadiness(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := service.CheckCurrentRecoveryCredentialBinding(masterVerifier, adminVerifier); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return recovery.Check(ctx)
	}
}
