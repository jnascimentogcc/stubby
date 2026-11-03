import {
  debounce,
  template,
} from 'lodash';

export const render = debounce((t: string) => template(t)({}), 50);
