# OpenSpec Clarify Best Practices

This document provides guidance for AI assistants on using the AskUserQuestion tool effectively during OpenSpec clarify workflows.

## Overview

The OpenSpec clarify-first approach emphasizes gathering critical decisions BEFORE creating any proposal documents. The AskUserQuestion tool is the primary mechanism for gathering these decisions interactively.

## When to Use AskUserQuestion

**ALWAYS use AskUserQuestion when:**

1. **Multiple valid approaches exist** - There are 2-4 reasonable implementation options
2. **User preferences determine the solution** - Different users might make different choices
3. **Trade-offs need validation** - Options have different cost/benefit profiles
4. **Architectural patterns are undecided** - The choice affects system structure
5. **Scope boundaries are unclear** - What's in scope vs. out of scope needs agreement
6. **Acceptance criteria need definition** - How we'll validate success

**Do NOT use AskUserQuestion for:**

- Questions with only one reasonable answer (use your judgment)
- Trivial implementation details (decide during implementation)
- Questions answerable from codebase inspection (research first)

## How to Structure Questions

### Question Format

Each AskUserQuestion call should include:

```python
{
  "questions": [
    {
      "question": "Clear question text ending with '?'",
      "header": "Short topic (max 12 chars)",
      "options": [
        {
          "label": "Concise label (1-5 words)",
          "description": "What this option means and its implications"
        },
        # ... 2-4 options total
      ],
      "multiSelect": false  # true only when multiple selections allowed
    }
  ]
}
```

### Best Practices

1. **Group related questions** - Ask up to 4 related questions together
2. **Clear, concise questions** - Provide context but stay focused
3. **Descriptive options** - Each option should clearly explain what it means
4. **Recommended first** - Put your recommended option first with "(Recommended)" suffix
5. **Appropriate headers** - Short topic labels (max 12 characters) display as chips/tags
6. **Multi-select sparingly** - Only use when options are NOT mutually exclusive

### Example: Good Question

```python
{
  "question": "How should we handle backward compatibility for the new API?",
  "header": "Compatibility",
  "options": [
    {
      "label": "Support both versions (Recommended)",
      "description": "Maintain old API alongside new one for 2 major versions. Higher maintenance cost but smoother migration."
    },
    {
      "label": "Deprecate old API",
      "description": "Mark old API as deprecated, remove in next major version. Faster cleanup but requires immediate migration."
    },
    {
      "label": "Adapter pattern",
      "description": "Implement adapter layer to translate old API calls to new implementation. More complex but cleaner separation."
    }
  ],
  "multiSelect": false
}
```

### Example: Bad Question

```python
# Bad: Only one reasonable answer
{
  "question": "Should we write tests?",
  "header": "Testing",
  "options": [
    {"label": "Yes", "description": "Write tests"},
    {"label": "No", "description": "Don't write tests"}
  ],
  "multiSelect": false
}
```

## Question Categories

Based on OpenSpec blocker categories, here are common question themes:

### Goal & Non-goals
- "What's the primary success metric for this feature?"
- "Which use cases are explicitly out of scope?"

### Interfaces & UX
- "What's the preferred API shape (functional vs object-oriented)?"
- "How should errors be presented to users?"
- "What level of configurability is needed?"

### Data & Migration
- "Do we need to support data migration from old format?"
- "Should the schema be extensible for future requirements?"

### Security & Permissions
- "What permission model should we use (role-based, attribute-based, etc.)?"
- "Do we need audit logging for this operation?"

### Acceptance Criteria
- "What level of test coverage is required (unit, integration, e2e)?"
- "Are there performance benchmarks we must meet?"

## Workflow Integration

### Step 0: Clarify-First

```python
# After reviewing codebase and identifying decisions

1. Categorize decisions as [Blocker] or [Non-blocker]
2. Use AskUserQuestion for ALL Blocker decisions
3. Use AskUserQuestion for Non-blockers if user input improves quality
4. STOP and wait for answers
```

### Step 1: Decision Log

```python
# After receiving answers

1. Output Decision Log with:
   - Confirmed choices (summarized from user selections)
   - Remaining open questions
   - Assumptions taken (with rationale)

2. If Blockers remain:
   - Use AskUserQuestion again with follow-ups (max 4)
   - STOP and wait again
```

## Common Pitfalls

### ❌ Don't: Ask Too Many Questions at Once

```python
# Bad: 10 questions in one call
{
  "questions": [ ... ]  # 10 questions - overwhelming!
}
```

### ✅ Do: Batch Related Questions

```python
# Good: 3-4 related questions, then wait
{
  "questions": [
    {"question": "API style?", ...},
    {"question": "Error handling?", ...},
    {"question": "Config approach?", ...}
  ]
}
# Later, after answers:
{
  "questions": [
    {"question": "Migration strategy?", ...},
    {"question": "Testing approach?", ...}
  ]
}
```

### ❌ Don't: Ignore User's "Other" Responses

When user selects "Other" and provides custom input:
- Read their response carefully
- If still unclear, ask follow-up with AskUserQuestion
- Don't make assumptions about their intent

### ✅ Do: Validate and Confirm

```python
# If user's "Other" response is ambiguous
{
  "questions": [
    {
      "question": "You mentioned X for the API style. Did you mean [specific interpretation]?",
      "header": "Confirm",
      "options": [
        {"label": "Yes, exactly", "description": "..."},
        {"label": "No, I meant", "description": "..."}
      ],
      "multiSelect": false
    }
  ]
}
```

## Tips for Different Scenarios

### New Feature Development
Focus on:
- Scope boundaries (what's in/out)
- API/interface design
- Acceptance criteria

### Refactoring
Focus on:
- Migration strategy
- Backward compatibility
- Performance requirements

### Bug Fixes
Focus on:
- Root cause approach (quick fix vs deeper fix)
- Test coverage for edge cases
- Regression prevention

### Performance Improvements
Focus on:
- Performance targets
- Measurement approach
- Trade-offs (memory vs speed, etc.)

## Examples

### Example 1: Feature Development

**Context:** User asks for a caching layer

```python
{
  "questions": [
    {
      "question": "What cache eviction strategy should we use?",
      "header": "Eviction",
      "options": [
        {
          "label": "LRU (Recommended)",
          "description": "Least Recently Used. Good general-purpose choice. Works well when recently accessed items are likely to be accessed again."
        },
        {
          "label": "TTL",
          "description": "Time-based expiration. Simpler to understand but may retain unused items or evict useful ones."
        },
        {
          "label": "LFU",
          "description": "Least Frequently Used. Better for access patterns with clear hot spots, but more complex to implement."
        }
      ],
      "multiSelect": false
    },
    {
      "question": "What cache invalidation approach do we need?",
      "header": "Invalidation",
      "options": [
        {
          "label": "Time-based (Recommended)",
          "description": "Cache entries expire after fixed time. Simple but may serve stale data."
        },
        {
          "label": "Event-based",
          "description": "Invalidate on data changes. More complex but always serves fresh data."
        },
        {
          "label": "Manual",
          "description": "Explicit invalidation calls. Most control but requires careful cache management."
        }
      ],
      "multiSelect": false
    }
  ]
}
```

### Example 2: API Design

**Context:** Adding async operation support

```python
{
  "questions": [
    {
      "question": "How should clients track async operation status?",
      "header": "Status API",
      "options": [
        {
          "label": "Polling endpoint (Recommended)",
          "description": "Provide GET /operations/{id} endpoint. Simple, works everywhere, but less efficient."
        },
        {
          "label": "Webhook callbacks",
          "description": "Call webhook when operation completes. More efficient but requires webhook registration infrastructure."
        },
        {
          "label": "WebSocket",
          "description": "Real-time status over persistent connection. Best UX but most complex to implement and scale."
        }
      ],
      "multiSelect": false
    }
  ]
}
```

### Example 3: Technical Trade-offs

**Context:** Choosing a serialization format

```python
{
  "questions": [
    {
      "question": "Which serialization format best fits your needs?",
      "header": "Format",
      "options": [
        {
          "label": "JSON (Recommended)",
          "description": "Human-readable, widely supported, good tooling. Larger size, slower parsing. Best for interoperability."
        },
        {
          "label": "MessagePack",
          "description": "Binary, compact, fast. Less readable, fewer tools. Best for performance-critical internal APIs."
        },
        {
          "label": "Protocol Buffers",
          "description": "Binary, schema-based, very fast. Requires schema management. Best for versioned, high-throughput systems."
        }
      ],
      "multiSelect": false
    }
  ]
}
```

## Summary

- **Use AskUserQuestion proactively** - Don't assume when you can ask
- **Ask early** - Gather decisions before writing proposal documents
- **Ask precisely** - Clear questions with well-defined options
- **Ask appropriately** - Focus on decisions that matter
- **Wait for answers** - Don't proceed with blockers unresolved
- **Document decisions** - Output a Decision Log after gathering answers

Following these practices ensures OpenSpec proposals are well-grounded in user decisions and minimizes rework during implementation.
