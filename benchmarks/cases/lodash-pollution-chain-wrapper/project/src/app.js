import _ from 'lodash';

export const pick = (obj) => _.chain(obj).pick(['a', 'b']).value();
