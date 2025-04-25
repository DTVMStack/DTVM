module.exports = {
  parserPreset: 'conventional-changelog-conventionalcommits',
  rules: {
    'body-leading-blank': [1, 'always'],
    'body-max-line-length': [2, 'always', 100],
    'footer-leading-blank': [1, 'always'],
    'footer-max-line-length': [2, 'always', 100],
    'header-max-length': [2, 'always', 100],
    'header-trim': [2, 'always'],
    'subject-case': [0, 'never'],
    'subject-empty': [2, 'never'],
    'subject-full-stop': [2, 'never', '.'],
    'type-case': [2, 'always', 'lower-case'],
    'type-empty': [2, 'never'],
    'type-enum': [
      2,
      'always',
      [
        'feat',
        'fix',
        'docs',
        'style',
        'refactor',
        'perf',
        'test',
        'build',
        'ci',
        'chore'
      ]
    ],
    'scope-enum': [
      2,
      'always',
      [
        'core',
        'runtime',
        'compiler',
        'examples',
        'docs',
        'tools',
        'deps',
        'ci',
        'test',
        'other',
        ''
      ]
    ]
  },
  prompt: {
    questions: {
      type: {
        description: 'Select the type of change that you\'re committing',
        enum: {
          feat: {
            description: 'A new feature',
            title: 'Features',
            emoji: '✨',
          },
          fix: {
            description: 'A bugfix',
            title: 'Bug Fixes',
            emoji: '🐛',
          },
          docs: {
            description: 'Documentation only changes',
            title: 'Documentation',
            emoji: '📚',
          },
          style: {
            description: 'Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)',
            title: 'Styles',
            emoji: '💎',
          },
          refactor: {
            description: 'A code change that neither fixes a bug nor adds a feature',
            title: 'Code Refactoring',
            emoji: '📦',
          },
          perf: {
            description: 'A code change that improves performance',
            title: 'Performance Improvements',
            emoji: '🚀',
          },
          test: {
            description: 'Adding missing tests or correcting existing tests',
            title: 'Tests',
            emoji: '🚨',
          },
          build: {
            description: 'Changes that affect the build system or external dependencies (example: cmake, bazel)',
            title: 'Builds',
            emoji: '🛠',
          },
          ci: {
            description: 'Changes to CI configuration files and scripts',
            title: 'Continuous Integrations',
            emoji: '⚙️',
          },
          chore: {
            description: 'Other changes that don\'t modify src or test files',
            title: 'Chores',
            emoji: '♻️',
          }
        }
      },
      scope: {
        description: 'What is the scope of this change (e.g. core, runtime, compiler)',
        enum: {
          core: {
            description: 'Core engine code',
          },
          runtime: {
            description: 'Runtime library',
          },
          compiler: {
            description: 'Compiler related',
          },
          examples: {
            description: 'Example code',
          },
          docs: {
            description: 'Documentation related',
          },
          tools: {
            description: 'Tool related',
          },
          deps: {
            description: 'Dependency related',
          },
          ci: {
            description: 'CI related',
          },
          test: {
            description: 'Test related',
          },
          other: {
            description: 'Other changes',
          }
        }
      },
      subject: {
        description: 'Write a short, imperative tense description of the change'
      },
      body: {
        description: 'Provide a longer description of the change'
      },
      isBreaking: {
        description: 'Are there any breaking changes?'
      },
      breaking: {
        description: 'Describe the breaking changes'
      },
      isIssueAffected: {
        description: 'Does this change affect any open issues?'
      },
      issues: {
        description: 'Add issue references (e.g. "Closes #123, #456")'
      }
    }
  }
}; 