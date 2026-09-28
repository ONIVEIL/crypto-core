module.exports = {
  testEnvironment: 'node',
  // @noble/* ship pure ESM — transform them like the project's own sources.
  transformIgnorePatterns: ['node_modules/(?!(@noble)/)'],
  // testUtils holds shared test helpers, not test suites of their own.
  testPathIgnorePatterns: ['/node_modules/', '<rootDir>/__tests__/testUtils/'],
};
