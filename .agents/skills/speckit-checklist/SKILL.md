---
name: speckit-checklist
description: Generate checklists for specific domains to ensure quality control and completeness verification during development.
---

# Checklist Generation

Generate checklists for specific domains to ensure quality control and completeness verification during development.

## User Input

Your input serves as the context. Specify the domain or feature for which to generate the checklist.

## Execution Steps

### 1. Determine Checklist Domain

Analyze user input to determine:
- The domain of the checklist (e.g., UX, security, performance, accessibility)
- The project's specific context
- Any relevant standards or regulations

### 2. Checklist Template

Check if a relevant checklist template exists:
- `.specify/templates/checklist-template.md`
- Any domain-specific checklist templates

### 3. Generate Checklist Items

Generate appropriate checklist items for the identified domain. The checklist should include:

#### Content Quality
- Content completeness and accuracy
- Clarity and conciseness
- Appropriate level of detail

#### Functionality
- Feature completeness
- Edge case handling
- Error handling

#### User Experience
- Usability
- Accessibility
- Performance
- Responsive design

#### Technical Quality
- Code quality
- Test coverage
- Documentation completeness
- Security considerations

#### Compliance
- Legal/regulatory requirements
- Organizational standards
- Industry best practices

### 4. Create Checklist File

Create the checklist file at the appropriate location:
- Feature checklist: `FEATURE_DIR/checklists/requirements.md`
- Domain checklist: `specs/checklists/DOMAIN.md`

### 5. Format Checklist

Use a consistent format:

```markdown
# Checklist: [Name]

## [Category]

- [ ] Check item 1
- [ ] Check item 2
- [ ] Check item 3

## Notes

[Any additional notes or context]
```

### 6. Report

Report the location of the checklist file and the total number of items.
