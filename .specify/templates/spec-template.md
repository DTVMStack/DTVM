# Feature Specification: [Feature Name]

**Feature Branch**: `[###-feature-name]`
**Created**: [DATE]
**Status**: Draft

---

## Authoritative References

<!--
  Purpose:
  - Keep `specs/modules/*` as the single source of truth (SSOT) for reusable domain module contracts and data models.
  - Feature specifications should not duplicate full OpenAPI / DTO / entity definitions.

  How to fill:
  - If this feature is a consumer (e.g. admin panel), list consumed modules and link to `specs/modules/MODULE/`.
  - If this feature introduces/changes reusable API contracts or data models, authoritative definitions must be updated in the relevant module SSOT.
-->

- **Consumed Modules**:
  - **[Module Name]**: [specs/modules/MODULE/](../../modules/MODULE/)

---

**Input**: User description: "$ARGUMENTS"

## User Scenarios & Testing *(Required)*

<!--
  Important: User Stories should be ordered by user journey priority.
  Each User Story / journey must be independently testable—even if only one is implemented,
  there should be a viable MVP that delivers value.

  Assign priority (P1, P2, P3, etc.) to each Story, where P1 is most critical.
  Treat each Story as an independent feature slice that can:
  - Be developed independently
  - Be tested independently
  - Be deployed independently
  - Be demonstrated to users independently
-->

### User Story 1 - [Brief Title] (Priority: P1)

[Describe this user journey in natural language]

**Priority Rationale**: [Explain the value and why this priority]

**Independent Testing**: [Describe how to test independently—e.g. "Can be fully tested via [specific action], delivering [specific value]"]

**Acceptance Scenarios**:

1. **Given** [initial state], **When** [action], **Then** [expected outcome]
2. **Given** [initial state], **When** [action], **Then** [expected outcome]

---

### User Story 2 - [Brief Title] (Priority: P2)

[Describe this user journey in natural language]

**Priority Rationale**: [Explain the value and why this priority]

**Independent Testing**: [Describe how to test independently]

**Acceptance Scenarios**:

1. **Given** [initial state], **When** [action], **Then** [expected outcome]

---

### User Story 3 - [Brief Title] (Priority: P3)

[Describe this user journey in natural language]

**Priority Rationale**: [Explain the value and why this priority]

**Independent Testing**: [Describe how to test independently]

**Acceptance Scenarios**:

1. **Given** [initial state], **When** [action], **Then** [expected outcome]

---

[Add more User Stories as needed, each with a priority assigned]

### Edge Cases

<!--
  Required: The following are placeholders.
  Replace with actual Edge Cases.
-->

- What happens when [boundary condition]?
- How does the system handle [error scenario]?

## Requirements *(Required)*

<!--
  Required: The following are placeholders.
  Replace with actual functional requirements.
-->

### Functional Requirements

- **FR-001**: The system must [specific capability, e.g. "allow users to create accounts"]
- **FR-002**: The system must [specific capability, e.g. "validate email addresses"]
- **FR-003**: Users must be able to [key interaction, e.g. "reset password"]
- **FR-004**: The system must [data requirement, e.g. "persist user preferences"]
- **FR-005**: The system must [behavior, e.g. "log all security events"]

*Example of marking underspecified requirements:*

- **FR-006**: The system must authenticate users via [TBD: authentication method not specified—email/password, SSO, OAuth?]
- **FR-007**: The system must retain user data [TBD: retention period not specified]

### Key Entities *(Required if feature involves data)*

- **[Entity 1]**: [What it represents, key attributes (no implementation details)]
- **[Entity 2]**: [What it represents, relationship with other entities]

## Success Criteria *(Required)*

<!--
  Required: Define measurable Success Criteria.
  These criteria must be technology-agnostic and measurable.
-->

### Measurable Outcomes

- **SC-001**: [Measurable metric, e.g. "Users can complete account creation within 2 minutes"]
- **SC-002**: [Measurable metric, e.g. "No performance degradation under 1000 concurrent users"]
- **SC-003**: [User satisfaction metric, e.g. "90% of users complete the main task on first attempt"]
- **SC-004**: [Business metric, e.g. "Reduce [X]-related tickets by 50%"]
