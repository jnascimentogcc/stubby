import { template } from 'lodash';

export const render = (tpl, data) => template(tpl)(data);
