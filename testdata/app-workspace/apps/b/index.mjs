import { add } from '../../packages/shared/index.mjs';
export const answer = () => add(20, 22);
// Deliberate finding unique to app B. Never called by the test.
export const evaluate = value => eval(value);
