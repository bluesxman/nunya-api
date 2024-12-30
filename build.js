const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['./src/index.ts'],
  bundle: true,
  minify: true,
  platform: 'node',
  target: 'node18',
  outfile: './dist/index.js',
  external: ['aws-sdk']
}).catch(() => process.exit(1));
