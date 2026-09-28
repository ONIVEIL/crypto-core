// Test-only Babel setup (the original app uses the React Native preset; this export needs no
// React Native toolchain).
module.exports = {
  presets: [
    ['@babel/preset-env', {targets: {node: 'current'}}],
    '@babel/preset-typescript',
  ],
};
