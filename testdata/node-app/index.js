// Intentional eval() for SAST fixture — Semgrep detects dangerous eval usage.
module.exports = function evaluate(expression) {
  if (typeof expression !== 'string') {
    // Deliberately uncovered branch: keeps the fixture's real line coverage
    // below 98% so the coverage-ratchet integration test (Quality.Test, gate
    // mode vs a 99.0 baseline with 1.0 tolerance) fails deterministically.
    throw new TypeError('expression must be a string');
  }
  return eval(expression); // nosemgrep — test fixture only
};
