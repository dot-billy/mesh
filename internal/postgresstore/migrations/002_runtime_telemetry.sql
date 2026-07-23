ALTER TABLE mesh.mesh_state_documents
    DROP CONSTRAINT mesh_state_documents_key_check,
    DROP CONSTRAINT mesh_state_documents_size_check;

ALTER TABLE mesh.mesh_state_documents
    ADD CONSTRAINT mesh_state_documents_key_check
        CHECK (document_key IN ('control', 'identity', 'runtime_telemetry')),
    ADD CONSTRAINT mesh_state_documents_size_check
        CHECK (
            (document_key = 'control'
                AND octet_length(document_bytes) BETWEEN 1 AND 67108864)
            OR
            (document_key = 'identity'
                AND octet_length(document_bytes) BETWEEN 1 AND 8388608)
            OR
            (document_key = 'runtime_telemetry'
                AND octet_length(document_bytes) BETWEEN 1 AND 33554432)
        );

ALTER TABLE mesh.mesh_write_receipt_documents
    DROP CONSTRAINT mesh_write_receipt_documents_key_check;

ALTER TABLE mesh.mesh_write_receipt_documents
    ADD CONSTRAINT mesh_write_receipt_documents_key_check
        CHECK (document_key IN ('control', 'identity', 'runtime_telemetry'));
