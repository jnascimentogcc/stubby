import _ from 'lodash';

export const read = (o) => _.get(o, 'a.b');
export const copy = (o) => _.cloneDeep(o);
