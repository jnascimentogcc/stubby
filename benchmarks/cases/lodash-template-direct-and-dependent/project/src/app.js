import { debounce } from 'lodash';
import lib from 'some-lib';

export const run = debounce(() => lib, 100);
