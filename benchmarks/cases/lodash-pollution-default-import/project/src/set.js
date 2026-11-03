import _ from 'lodash';

export const assign = (target, path, value) => _.set(target, path, value);
