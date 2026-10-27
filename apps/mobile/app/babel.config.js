module.exports = {
  presets: ['module:@react-native/babel-preset'],
  // zod 4 uses `export * as ns from`, which Hermes does not parse.
  plugins: ['@babel/plugin-transform-export-namespace-from'],
};
