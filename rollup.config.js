// rollup.config.js
import alias from '@rollup/plugin-alias'
import { nodeResolve } from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import builtins from 'rollup-plugin-node-builtins'
import nodePolyfills from 'rollup-plugin-node-polyfills'

import json from '@rollup/plugin-json'
import pkg from './package.json'

export default {
  input: 'src/index.js',
  output: [{
    file: pkg.main,
    format: 'es' // Default: "es"
  }
  // ,
  // {
  //   file: pkg.module,
  //   format: 'es' // Default: "es"
  // }
  ],
  plugins: [
    alias({
      entries: [
        // { find: 'crypto', replacement: 'crypto-browserify' },
        // { find: 'stream', replacement: 'stream-browserify' },
        // { find: 'process', replacement: 'process/browserify' },
        // { find: 'buffer', replacement: 'buffer/' }
      ]
    }),
    json(),
    nodeResolve(
      {
        browser: true, // instructs the plugin to use the "browser" property in package.json files to specify alternative files to load for bundling
        preferBuiltins: true
      }
    ),
    commonjs({
      extensions: ['.mjs', '.js'],
      requireReturnsDefault: 'auto' // what is returned when requiring an ES module from a CommonJS file
    }),
    nodePolyfills(),
    builtins()
  ]
}
