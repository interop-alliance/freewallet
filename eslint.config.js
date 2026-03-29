import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import react from 'eslint-plugin-react'
import prettierConfig from 'eslint-config-prettier'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
      react.configs.flat.recommended, // added
      react.configs.flat['jsx-runtime'], // added — suppresses react/react-in-jsx-scope
      prettierConfig // added — must be last in extends
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        // added — needed for type-aware lint rules
        project: ['./tsconfig.app.json', './tsconfig.node.json']
      }
    },
    settings: {
      react: { version: 'detect' } // added
    },
    rules: {
      // From @typescript-eslint recommended — already included, but be explicit:
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_'
        }
      ],
      '@typescript-eslint/no-explicit-any': 'off',
      // Always require curly braces
      curly: ['error', 'all'],

      // Prefer modern JS
      'no-var': 'error',
      'prefer-const': 'error',

      // React:
      'react/react-in-jsx-scope': 'off',
      'react-refresh/only-export-components': 'warn' // warn, not error
    }
  }
])
