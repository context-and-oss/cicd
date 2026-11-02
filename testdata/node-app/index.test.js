const evaluate = require('./index');

test('evaluate adds numbers', () => {
  expect(evaluate('1 + 1')).toBe(2);
});
