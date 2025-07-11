import config from 'eslint-config-standard-universal'
import tseslint from 'typescript-eslint'
import _globals from 'globals'

export default tseslint.config(
  ...config(_globals.node),
  {
    languageOptions: {
      parserOptions: {
        tsconfigRootDir: import.meta.dirname
      }
    }
  }
)
