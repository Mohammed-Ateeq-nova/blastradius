// DEMO FIXTURE entry file. Static import only; not executed by BlastRadius.
const _ = require("lodash");

module.exports = function demo() {
  return _.identity("fixture");
};
