// rv.reg — public surface of the parser library. Everything above attaches
// to RV.reg already; this file is the stable list of names consumers use.
(function (RV) {
  'use strict';

  // Attach nothing new — just freeze the namespace shape so accidental
  // reassignment fails loudly in strict mode.
  Object.freeze(RV.reg.consts);
  Object.freeze(RV.reg.filetime);

  RV.reg.version = '0.1.0';
})(window.RV);
