import _ from 'lodash';

const cache = new Map();
export const remember = (k, v) => cache.set(k, v);
export const read = (o) => _.get(o, 'a');
