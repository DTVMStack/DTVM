# Commit Convention

To maintain consistency and readability in the codebase, all commits to this project should follow the convention below. These conventions are based on [Conventional Commits](https://www.conventionalcommits.org/).

## Commit Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer]
```

### Type

Must be one of the following:

- **feat**: A new feature
- **fix**: A bugfix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing or correcting existing tests
- **build**: Changes that affect the build system or external dependencies (example: cmake, bazel)
- **ci**: Changes to CI configuration files and scripts
- **chore**: Other changes that don't modify src or test files

### Scope

The scope should specify the area of the change, for example:

- **core**: Core engine code
- **runtime**: Runtime library
- **compiler**: Compiler related
- **examples**: Example code
- **docs**: Documentation related
- **tools**: Tool related
- **deps**: Dependency related
- **ci**: CI related
- **test**: Test related
- **other**: Other

### Description

- Use the imperative, present tense: "change" not "changed" or "changes"
- Don't capitalize the first letter
- No period at the end

### Body

- Use the imperative, present tense
- Should include the motivation for the change and contrast this with previous behavior

### Footer

- **BREAKING CHANGE**: Should start with "BREAKING CHANGE:" followed by a space or two newlines, then a description of the change
- References to issues: Can reference related issues, e.g., "Closes #123, #456"

## Examples

```
feat(core): add WASM runtime binding support

Add support for WASM runtime bindings, making it easier for developers to call native functions.

BREAKING CHANGE: Runtime API now requires explicit initialization, previous implicit initialization is no longer supported.
Closes #123
```

```
fix(runtime): fix memory leak in memory management

Fix memory leak that could occur when repeatedly creating and destroying VM instances.

Closes #456
```

```
docs: update API documentation and usage examples
```

## Automatic Validation

All commits will be automatically validated using GitHub Actions to ensure they comply with the above conventions. Commits that do not comply with the convention may be automatically rejected. 