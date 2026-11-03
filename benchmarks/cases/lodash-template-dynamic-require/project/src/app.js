import { debounce } from 'lodash';

export const run = debounce(() => 1, 100);
export const plugin = require(process.env.PLUGIN);
