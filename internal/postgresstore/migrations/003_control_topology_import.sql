ALTER TABLE mesh.mesh_import_metadata
    DROP CONSTRAINT mesh_import_metadata_control_version_check;

ALTER TABLE mesh.mesh_import_metadata
    ADD CONSTRAINT mesh_import_metadata_control_version_check
        CHECK (source_control_version IN (2, 3));
