import type { template } from 'lodash';
import { debounce } from 'lodash';

export type Tpl = typeof template;
export const run = debounce(() => 1, 100);
