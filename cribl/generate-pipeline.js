'use strict';

// Regenerates the Code function body inside forge_win_ecs.pipeline.json from
// winxml_to_ecs.js, which is the single source of truth.
//
//   node cribl/generate-pipeline.js          # rewrite the pipeline JSON
//   node cribl/generate-pipeline.js --check  # fail if it is stale (CI-friendly)
//
// winxml_to_ecs.js was already documented as the source of truth and the file
// this generator is named in its header, but the generator itself was never
// committed -- so the embedded copy could silently drift from the tested code.
// Everything below is derived via Function.prototype.toString(); nothing is
// hand-copied.

var fs = require('fs');
var path = require('path');
var m = require('./winxml_to_ecs.js');

var PIPELINE = path.join(__dirname, 'forge_win_ecs.pipeline.json');

// Cribl's Code function wraps the submitted string as the body of its own
// exports.process(__e), so we emit the helper declarations (hoisted, order is
// irrelevant) followed by applyToEvent's *body* rather than the function itself.
var HELPERS = [
  m.unescapeXml,
  m.hexToDecimal,
  m.basename,
  m.stripIpv4Mapped,
  m.sysmonVal,
  m.splitDomainUser,
  m.parseHashes,
  m.sysmonProcess,
  m.splitArgs,
  m.extractEventData
];

function bodyOf(fn) {
  var src = fn.toString();
  var open = src.indexOf('{');
  var close = src.lastIndexOf('}');
  if (open < 0 || close < 0) throw new Error('cannot locate function body');
  return src.slice(open + 1, close).replace(/^\n+|\s+$/g, '');
}

function buildCode() {
  var parts = HELPERS.map(function (fn) { return fn.toString(); });
  parts.push(bodyOf(m.applyToEvent));
  return parts.join('\n\n') + '\n';
}

function main() {
  var check = process.argv.indexOf('--check') !== -1;
  var pipeline = JSON.parse(fs.readFileSync(PIPELINE, 'utf8'));

  var codeFn = pipeline.conf.functions.filter(function (f) { return f.id === 'code'; })[0];
  if (!codeFn) throw new Error('no "code" function in ' + PIPELINE);

  var next = buildCode();
  if (codeFn.conf.code === next) {
    console.log('forge_win_ecs.pipeline.json is up to date with winxml_to_ecs.js');
    return;
  }
  if (check) {
    console.error('STALE: forge_win_ecs.pipeline.json does not match winxml_to_ecs.js');
    console.error('Run: node cribl/generate-pipeline.js');
    process.exit(1);
  }

  codeFn.conf.code = next;
  fs.writeFileSync(PIPELINE, JSON.stringify(pipeline, null, 2) + '\n');
  console.log('regenerated the Code function in forge_win_ecs.pipeline.json (' + next.length + ' chars)');
}

main();
