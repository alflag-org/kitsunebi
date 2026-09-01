# Product

## Register

product

## Users

Platform administrators, operators, service maintainers, and auditors use Kitsunebi at a desktop workstation during routine operations and incident response. They need to understand the relationship between a Service, its ClusterRevision, Worlds, Execution Units, and External Endpoints, then make an explicit, reviewable change.

## Product Purpose

Kitsunebi is the MCPlayNetwork control plane. It describes service intent and ownership while GameAP 4 runs Minecraft processes and provides low-level console and file capabilities. Operators should be able to observe desired versus observed state, prepare a change, inspect its diff and backup, verify the result, and accept or roll back it with an audit trail.

## Brand Personality

Exact, calm, operational. The interface should reduce cognitive load under pressure and explain unknown or fail-closed states instead of hiding them.

## Anti-references

Do not resemble a generic game-hosting panel, a GameAP link directory, Minecraft decoration, a dark terminal dashboard, a SaaS hero-metric page, or a dense grid of identical nested cards. Avoid automatic reconciliation and controls that imply an action without a real API operation behind them.

## Design Principles

- Keep service intent separate from execution infrastructure.
- Make every mutation explicit, bounded, and reversible where possible.
- Show hierarchy and evidence before offering an action.
- Treat unknown capabilities and drift as explainable operational states.
- Keep the management plane from becoming a dependency for running services.

## Accessibility & Inclusion

Target WCAG 2.2 AA. All workflows must work with keyboard navigation, visible focus, 200% zoom, semantic status text (never color alone), and reduced-motion preferences. Touch targets are at least 44px. Core functions remain available on tablet and mobile layouts.
