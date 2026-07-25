CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA mesh;

CREATE TABLE mesh.mesh_write_receipts (
    receipt_id uuid PRIMARY KEY,
    operation_class text NOT NULL,
    committed_at timestamptz NOT NULL,
    CONSTRAINT mesh_write_receipts_operation_class_check
        CHECK (operation_class ~ '^[a-z][a-z0-9_.-]{0,63}$')
);

CREATE TABLE mesh.mesh_state_documents (
    document_key text PRIMARY KEY,
    revision bigint NOT NULL,
    document_bytes bytea NOT NULL,
    document_sha256 bytea NOT NULL,
    last_write_receipt uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT mesh_state_documents_key_check
        CHECK (document_key IN ('control', 'identity')),
    CONSTRAINT mesh_state_documents_revision_check
        CHECK (revision > 0 AND revision < 9223372036854775807),
    CONSTRAINT mesh_state_documents_sha256_size_check
        CHECK (octet_length(document_sha256) = 32),
    CONSTRAINT mesh_state_documents_sha256_check
        CHECK (document_sha256 = mesh.digest(document_bytes, 'sha256')),
    CONSTRAINT mesh_state_documents_size_check
        CHECK (
            (document_key = 'control'
                AND octet_length(document_bytes) BETWEEN 1 AND 67108864)
            OR
            (document_key = 'identity'
                AND octet_length(document_bytes) BETWEEN 1 AND 8388608)
        ),
    CONSTRAINT mesh_state_documents_receipt_fkey
        FOREIGN KEY (last_write_receipt)
        REFERENCES mesh.mesh_write_receipts(receipt_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE mesh.mesh_write_receipt_documents (
    receipt_id uuid NOT NULL,
    document_key text NOT NULL,
    base_revision bigint NOT NULL,
    committed_revision bigint NOT NULL,
    document_sha256 bytea NOT NULL,
    CONSTRAINT mesh_write_receipt_documents_receipt_fkey
        FOREIGN KEY (receipt_id)
        REFERENCES mesh.mesh_write_receipts(receipt_id)
        ON DELETE RESTRICT,
    CONSTRAINT mesh_write_receipt_documents_document_fkey
        FOREIGN KEY (document_key)
        REFERENCES mesh.mesh_state_documents(document_key)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT mesh_write_receipt_documents_key_check
        CHECK (document_key IN ('control', 'identity')),
    CONSTRAINT mesh_write_receipt_documents_base_revision_check
        CHECK (base_revision >= 0),
    CONSTRAINT mesh_write_receipt_documents_committed_revision_check
        CHECK (committed_revision = base_revision + 1),
    CONSTRAINT mesh_write_receipt_documents_sha256_size_check
        CHECK (octet_length(document_sha256) = 32),
    PRIMARY KEY (receipt_id, document_key),
    UNIQUE (document_key, committed_revision),
    UNIQUE (receipt_id, document_key, committed_revision, document_sha256)
);

ALTER TABLE mesh.mesh_state_documents
    ADD CONSTRAINT mesh_state_documents_receipt_item_fkey
    FOREIGN KEY (last_write_receipt, document_key, revision, document_sha256)
    REFERENCES mesh.mesh_write_receipt_documents
        (receipt_id, document_key, committed_revision, document_sha256)
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX mesh_write_receipts_committed_at_idx
    ON mesh.mesh_write_receipts (committed_at);

CREATE TABLE mesh.mesh_import_metadata (
    singleton smallint PRIMARY KEY,
    import_id uuid NOT NULL UNIQUE,
    import_receipt uuid NOT NULL UNIQUE,
    source_format text NOT NULL,
    source_control_sha256 bytea NOT NULL,
    source_identity_sha256 bytea NOT NULL,
    source_control_bytes bigint NOT NULL,
    source_identity_bytes bigint NOT NULL,
    source_control_version integer NOT NULL,
    source_identity_schema text NOT NULL,
    source_backup_id text NOT NULL,
    imported_at timestamptz NOT NULL,
    importer_build text NOT NULL,
    CONSTRAINT mesh_import_metadata_singleton_check
        CHECK (singleton = 1),
    CONSTRAINT mesh_import_metadata_receipt_fkey
        FOREIGN KEY (import_receipt)
        REFERENCES mesh.mesh_write_receipts(receipt_id)
        ON DELETE RESTRICT,
    CONSTRAINT mesh_import_metadata_source_format_check
        CHECK (source_format = 'mesh-json-two-document-v1'),
    CONSTRAINT mesh_import_metadata_control_sha256_size_check
        CHECK (octet_length(source_control_sha256) = 32),
    CONSTRAINT mesh_import_metadata_identity_sha256_size_check
        CHECK (octet_length(source_identity_sha256) = 32),
    CONSTRAINT mesh_import_metadata_control_bytes_check
        CHECK (source_control_bytes BETWEEN 1 AND 67108864),
    CONSTRAINT mesh_import_metadata_identity_bytes_check
        CHECK (source_identity_bytes BETWEEN 1 AND 8388608),
    CONSTRAINT mesh_import_metadata_control_version_check
        CHECK (source_control_version = 2),
    CONSTRAINT mesh_import_metadata_identity_schema_check
        CHECK (source_identity_schema = 'identity-state-v2'),
    CONSTRAINT mesh_import_metadata_backup_id_check
        CHECK (octet_length(source_backup_id) = 32 AND source_backup_id ~ '^[0-9a-f]+$'),
    CONSTRAINT mesh_import_metadata_importer_build_check
        CHECK (importer_build ~ '^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,255}$')
);
