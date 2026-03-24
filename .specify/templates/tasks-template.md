# Task List: [Feature Name]

**Input**: Design documents from `/specs/features/[###-feature-name]/`
**Prerequisites**: plan.md (required), spec.md (User Stories required), research.md, data-model.md, contracts/

**Tests**: The following examples include test tasks. Tests are optional—include only when explicitly required in the feature spec.

**Organization**: Tasks are grouped by User Story to support independent implementation and testing of each Story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: User Story (e.g. US1, US2, US3)
- Description includes exact file path

## Path Conventions

- **Monolith project**: `src/`, `tests/` under repository root
- **Web app**: `backend/src/`, `frontend/src/`
- **Mobile**: `api/src/`, `ios/src/` or `android/src/`
- Paths below assume monolith—adjust per plan.md structure

<!--
  ============================================================================
  Important: The following tasks are example placeholders for illustration only.

  The speckit-tasks skill must replace them with actual tasks based on:
  - User Stories in spec.md (with priorities P1, P2, P3...)
  - Functional requirements in plan.md
  - Entities in data-model.md
  - Endpoints in contracts/

  Tasks must be organized by User Story so each Story can:
  - Be implemented independently
  - Be tested independently
  - Be delivered as MVP increment

  Do NOT retain these example tasks in generated tasks.md files.
  ============================================================================
-->

## Phase 1: Project Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [ ] T001 Create project structure per implementation plan
- [ ] T002 Initialize [language] project, configure [framework] dependencies
- [ ] T003 [P] Configure code checking and formatting tools

---

## Phase 2: Infrastructure (Blocking Prerequisites)

**Purpose**: Core infrastructure that must be completed before any User Story

**⚠️ Critical**: Do NOT start any User Story until this phase is complete

Base task examples (adjust per project):

- [ ] T004 Set up database schema and migration framework
- [ ] T005 [P] Implement authentication/authorization framework
- [ ] T006 [P] Set up API routing and middleware structure
- [ ] T007 Create base models/entities required by all stories
- [ ] T008 Configure error handling and logging infrastructure
- [ ] T009 Set up environment configuration management

**Checkpoint**: Infrastructure ready—User Story implementation can now begin

---

## Phase 3: User Story 1 - [Title] (Priority: P1) 🎯 MVP

**Goal**: [Brief description of what this story delivers]

**Independent Testing**: [How to verify this story runs independently]

### User Story 1 Tests (optional—include only when explicitly required) ⚠️

> **Note: Write these tests first, ensure they fail before implementation**

- [ ] T010 [P] [US1] Contract test for endpoint [endpoint] tests/contract/test_[name].py
- [ ] T011 [P] [US1] Integration test for user journey [journey] tests/integration/test_[name].py

### User Story 1 Implementation

- [ ] T012 [P] [US1] Create [Entity1] model src/models/[entity1].py
- [ ] T013 [P] [US1] Create [Entity2] model src/models/[entity2].py
- [ ] T014 [US1] Implement [Service] src/services/[service].py (depends on T012, T013)
- [ ] T015 [US1] Implement [endpoint/feature] src/[location]/[file].py
- [ ] T016 [US1] Add validation and error handling
- [ ] T017 [US1] Add logging for User Story 1 operations

**Checkpoint**: User Story 1 should now be fully usable and independently testable

---

## Phase 4: User Story 2 - [Title] (Priority: P2)

**Goal**: [Brief description of what this story delivers]

**Independent Testing**: [How to verify this story runs independently]

### User Story 2 Tests (optional—include only when explicitly required) ⚠️

- [ ] T018 [P] [US2] Contract test for endpoint [endpoint] tests/contract/test_[name].py
- [ ] T019 [P] [US2] Integration test for user journey [journey] tests/integration/test_[name].py

### User Story 2 Implementation

- [ ] T020 [P] [US2] Create [Entity] model src/models/[entity].py
- [ ] T021 [US2] Implement [Service] src/services/[service].py
- [ ] T022 [US2] Implement [endpoint/feature] src/[location]/[file].py
- [ ] T023 [US2] Integrate with User Story 1 components (if needed)

**Checkpoint**: Both User Story 1 and 2 should now work independently

---

## Phase 5: User Story 3 - [Title] (Priority: P3)

**Goal**: [Brief description of what this story delivers]

**Independent Testing**: [How to verify this story runs independently]

### User Story 3 Tests (optional—include only when explicitly required) ⚠️

- [ ] T024 [P] [US3] Contract test for endpoint [endpoint] tests/contract/test_[name].py
- [ ] T025 [P] [US3] Integration test for user journey [journey] tests/integration/test_[name].py

### User Story 3 Implementation

- [ ] T026 [P] [US3] Create [Entity] model src/models/[entity].py
- [ ] T027 [US3] Implement [Service] src/services/[service].py
- [ ] T028 [US3] Implement [endpoint/feature] src/[location]/[file].py

**Checkpoint**: All User Stories should now run independently

---

[Add more User Story phases as needed, following the same pattern]

---

## Phase N: Polish and Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple User Stories

- [ ] TXXX [P] Update documentation in docs/
- [ ] TXXX Code cleanup and refactoring
- [ ] TXXX Cross-story performance optimization
- [ ] TXXX [P] Add unit tests (if required) tests/unit/
- [ ] TXXX Security hardening
- [ ] TXXX Run quickstart.md verification

---

## Dependencies and Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies—can start immediately
- **Infrastructure (Phase 2)**: Depends on setup completion—blocks all User Stories
- **User Stories (Phase 3+)**: All depend on infrastructure phase completion
  - User Stories can be advanced in parallel (if resources allow)
  - Or advance by priority order (P1 → P2 → P3)
- **Polish (final phase)**: Depends on completion of all target User Stories

### Dependencies Between User Stories

- **User Story 1 (P1)**: Can start after Infrastructure (Phase 2) completes—no dependency on other Stories
- **User Story 2 (P2)**: Can start after Infrastructure (Phase 2) completes—may integrate with US1 but should be independently testable
- **User Story 3 (P3)**: Can start after Infrastructure (Phase 2) completes—may integrate with US1/US2 but should be independently testable

### Within Each User Story

- Tests (if included) must be written first and confirmed failing before implementation
- Models before services
- Services before endpoints
- Core implementation before integration
- Move to next priority only after current Story is complete

### Parallelization Opportunities

- All [P]-labeled setup tasks can run in parallel
- All [P]-labeled infrastructure tasks can run in parallel within Phase 2
- After infrastructure phase completes, all User Stories can start in parallel (if team has capacity)
- All [P]-labeled tests within a User Story can run in parallel
- [P]-labeled models within a Story can run in parallel
- Different User Stories can be developed in parallel by different team members

---

## Parallel Example: User Story 1

```bash
# Start all User Story 1 tests (if required) simultaneously:
Task: "Contract test for endpoint [endpoint] tests/contract/test_[name].py"
Task: "Integration test for user journey [journey] tests/integration/test_[name].py"

# Start all User Story 1 models simultaneously:
Task: "Create [Entity1] model src/models/[entity1].py"
Task: "Create [Entity2] model src/models/[entity2].py"
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Infrastructure (critical—blocks all Stories)
3. Complete Phase 3: User Story 1
4. **Pause for verification**: Independently test User Story 1
5. Ship when deployable/demonstrable

### Incremental Delivery

1. Complete setup + infrastructure → Base ready
2. Add User Story 1 → Independent test → Deploy/demo (MVP!)
3. Add User Story 2 → Independent test → Deploy/demo
4. Add User Story 3 → Independent test → Deploy/demo
5. Each Story adds value without breaking existing Stories

### Parallel Team Strategy

With multiple developers:

1. Team completes setup + infrastructure together
2. After infrastructure completes:
   - Developer A: User Story 1
   - Developer B: User Story 2
   - Developer C: User Story 3
3. Each Story completed and integrated independently

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps tasks to specific User Story for traceability
- Each User Story should be completable and testable independently
- Verify tests fail first before starting implementation
- Commit after each task or logic group completes
- Pause at any Checkpoint to independently verify Story
- Avoid: vague tasks, same-file conflicts, cross-Story dependencies that break independence
