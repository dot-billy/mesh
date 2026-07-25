// Package supervisedchild defines the platform-neutral state machine for a
// directly supervised Nebula child.
//
// It deliberately contains no os/exec or filesystem gate implementation. A
// platform may select this controller only after its Process and Gate adapters
// can prove native identity, durability, and teardown behavior.
package supervisedchild
