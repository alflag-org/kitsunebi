# Design

## Direction

An operational instrument for a bright desktop workstation: clear paper-white surfaces, disciplined dividers, and one oxidized-teal signal color. The visual system is quiet enough for incident response, with rust-copper reserved for selected or cautionary decisions.

## Color

Use OKLCH tokens. Primary: `oklch(0.450 0.086 170)`. Body background is pure white; surfaces are cool near-white neutrals; ink is near-black low-chroma teal. Semantic green, amber, and red only describe actual state. Keep contrast at WCAG AA.

## Typography

Use one system humanist sans family (`ui-sans-serif, system-ui, sans-serif`) with a fixed rem scale. Headings are compact and sentence case. Tabular numerals are used for counts, timestamps, and identifiers. Body copy stays readable at 65–75ch.

## Layout

Desktop uses a persistent left navigation and a bounded content canvas with a right operations rail. Tablet uses master/detail. Mobile uses a drawer and single column without hiding core functions. Prefer tables, dividers, and definition lists over nested cards. Use 44px controls, `:focus-visible`, semantic landmarks, and a skip link.

## Components

Shared primitives include navigation, breadcrumbs, status badges with text, data tables, detail rows, empty/error/loading states, change-session headers, and a danger confirmation dialog. Mutation controls always identify the target, impact, rollback availability, and request state.

## Motion

State-only transitions use 150–250ms and never gate content. Respect `prefers-reduced-motion: reduce` by removing transitions. No decorative parallax, bounce, or continuous animation.
