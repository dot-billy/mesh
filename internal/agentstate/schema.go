// Package agentstate defines the stable compatibility boundary for the
// node-agent state persisted across package upgrades and rollbacks.
package agentstate

// CurrentSchemaVersion is the schema written by this source revision.
const CurrentSchemaVersion = 2

// CurrentWriteVersion names CurrentSchemaVersion in release-compatibility
// checks, where it must be distinguished from the inclusive reader range.
const CurrentWriteVersion = CurrentSchemaVersion
