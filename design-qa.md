# Design QA — Node action placement

## Comparison target

- Source visual truth: `/home/uwadmin/.codex/attachments/882a7636-a445-4e57-b04e-575efbe17901/image-1.png`
- Live implementation: `https://mesh-174-138-61-100.sslip.io`
- Desktop implementation capture: `/home/uwadmin/mesh/validation/node-actions-20260724/final-live/desktop-node-actions.png`
- Mobile implementation capture: `/home/uwadmin/mesh/validation/node-actions-20260724/final-live/mobile-node-actions.png`
- Full-view comparison: `/home/uwadmin/mesh/validation/node-actions-20260724/source-implementation-comparison.png`
- Browser evidence: `/home/uwadmin/mesh/validation/node-actions-20260724/final-live/layout.json`
- Source pixels: `2926 × 1166`
- Desktop implementation pixels: `2174 × 896`
- Desktop CSS viewport: `1467 × 900` at device scale factor `2`
- Mobile implementation pixels: `732 × 1714`
- Mobile CSS viewport: `390 × 844` at device scale factor `2`
- Density normalization: the source was resized proportionally to an `896 px` comparison height (`2248 × 896`) and stacked with the desktop implementation capture. The implementation content was not stretched.
- State: authenticated administrator, `mac-client-test`, “Manage nodes (2)” expanded, two operational nodes with seven lifecycle actions each.

The source screenshot is the reported defect state, not a layout to preserve. The acceptance target is the same product state with the action controls placed below the identity, health, and status information instead of compressed into a narrow right-hand rail.

## Findings

No actionable P0, P1, or P2 findings remain.

### Required fidelity surfaces

| Surface | Result | Evidence |
| --- | --- | --- |
| Fonts and typography | Passed | The implementation retains the existing Mesh font stacks, sizes, weights, line heights, and uppercase status treatment. Button labels remain legible, do not truncate, and use the product’s established compact control weight. |
| Spacing and layout rhythm | Passed | On desktop, each action group occupies a full-width footer (`1045 × 49 px`) below node information and status. Rows fell from `248 px` in the defect capture to `182 px` and `197 px`. On mobile, actions form a two-column `326 × 175 px` grid below the status; rows fell from `561/677 px` to `379/409 px`. There is no content or status overlap. |
| Colors and visual tokens | Passed | Existing background, border, text, accent, warning, and danger tokens are preserved. Routine controls are neutral; recovery and rotation retain the accent; replacement remains warning-colored; revocation remains danger-colored. Contrast and hierarchy are consistent with the surrounding interface. |
| Image quality and asset fidelity | Passed | This screen contains no photographic, illustrative, logo, or generated raster assets. The existing Font Awesome list icon remains sharp and unchanged; no visible source asset was replaced with CSS or handcrafted artwork. |
| Copy and content | Passed | All node identity, placement, heartbeat, health, status, and action labels remain intact. The placement fix does not remove or rename any operator action. |
| Responsive behavior | Passed | The desktop document has `clientWidth = scrollWidth = 1467`; mobile has `clientWidth = scrollWidth = 390`. No horizontal overflow occurs. All buttons remain within their node row. The last mobile action can be scrolled above the fixed navigation (`button bottom 646 px`, navigation top `772 px`). |
| Accessibility and interaction | Passed | Each toolbar is exposed as a named `role="group"` with `aria-label="Actions for {node name}"`. The safe primary actions tested—Edit placement, Security & access, and Edit routes—opened their expected dialogs. The browser console reported no errors. |

## Comparison history

1. **P1 — Actions compressed into a narrow right rail.**
   The source and initial live capture placed seven controls into a `210 × 224 px` desktop column, separate from the reading flow. On mobile the column narrowed to `157 px`, produced `314 px` of controls, and forced rows to `561 px` and `677 px`. `actionAfterContent` was false for every node.

2. **Fix applied.**
   The node row now uses explicit information, status, and action grid areas. The action group spans the full row below the node content, uses compact product-aligned secondary controls, and becomes a two-column grid at `760 px` and below. A separator establishes the toolbar as a footer without visually detaching it from the node.

3. **Post-fix live comparison.**
   The refreshed desktop rows measure `1069 × 182 px` and `1069 × 197 px`, with `1045 × 49 px` full-width action footers. Mobile rows measure `350 × 379 px` and `350 × 409 px`, each with a `326 × 175 px` action grid. For all four measured rows, actions are after content, do not overlap information or status, remain inside the row, and have the expected accessible name.

## Interaction and runtime evidence

- Live readiness returned successfully before browser verification.
- Edit placement opened `#topology-dialog`.
- Security & access opened `#node-security-dialog`.
- Edit routes opened `#route-profile-dialog`.
- No destructive lifecycle action was executed during QA.
- Browser errors: none.
- Desktop horizontal overflow: none.
- Mobile horizontal overflow: none.
- Mobile controls remain reachable above the fixed bottom navigation.

## Focused region evidence

The combined comparison keeps the complete node-management region large enough to read its typography, status alignment, separators, and all seven controls, so no separate desktop crop was required. The dedicated mobile capture supplies the focused responsive evidence needed to assess label wrapping, two-column alignment, row height, and bottom-navigation clearance.

## Accepted differences

- The final implementation intentionally does not reproduce the source’s broken right-hand action rail.
- Heartbeat sequence numbers and timestamps changed naturally between captures.
- Source and implementation captures have different aspect ratios; the comparison normalizes by height and preserves both images’ proportions.
- The final desktop capture begins slightly lower in the surrounding page because it was taken from the live, continuously updating deployment. The complete “Manage nodes” region remains visible.

## Follow-up polish

No blocking follow-up is required. Moving lower-frequency lifecycle actions into a “More actions” menu could be explored later, but that would change the interaction model and is outside this placement fix.

final result: passed
