'use strict';

// Reads eforge/attack.yaml's environment.systems[] and emits
// cribl/lookups/forge-assets.csv, keyed on host.name, for a Cribl Lookup
// function wired into forge_win_ecs.pipeline.json (see generate-pipeline.js
// for the equivalent "regenerate from source of truth" pattern).
//
// attack.yaml only has ~2 lists we care about (environment.users,
// environment.systems), each a flat sequence of `key: value` mappings with
// consistent indentation -- not worth pulling in a YAML dependency for, so
// this is a small targeted parser for exactly that shape, not a general YAML
// parser. If attack.yaml's structure changes beyond this shape, this breaks
// loudly (a thrown error), not silently.
//
//   node cribl/generate-assets-lookup.js          # rewrite the CSV
//   node cribl/generate-assets-lookup.js --check  # fail if it is stale

var fs = require('fs');
var path = require('path');

var ATTACK_YAML = path.join(__dirname, '..', 'eforge', 'attack.yaml');
var CSV_OUT = path.join(__dirname, 'lookups', 'forge-assets.csv');

// Pulls a top-level "key:" block's list items out of the YAML text. Each item
// starts with "  - field: value" and continues with "    field: value" lines
// at the same or deeper indent, ending at a blank line, a dedent back to the
// list marker's indent or shallower on a non-"- " line, or EOF.
function parseYamlList(text, listKey) {
  var lines = text.split('\n');
  var startIdx = -1;
  var keyIndent = -1;
  for (var i = 0; i < lines.length; i++) {
    var m = /^(\s*)([A-Za-z_][\w]*):\s*$/.exec(lines[i]);
    if (m && m[2] === listKey) {
      startIdx = i + 1;
      keyIndent = m[1].length;
      break;
    }
  }
  if (startIdx < 0) throw new Error('could not find "' + listKey + ':" in ' + ATTACK_YAML);

  var items = [];
  var current = null;
  var itemIndent = -1;

  for (var j = startIdx; j < lines.length; j++) {
    var line = lines[j];
    if (/^\s*$/.test(line)) continue; // blank line inside a list is fine

    var indent = line.match(/^\s*/)[0].length;
    var dashMatch = /^(\s*)-\s+([A-Za-z_][\w]*):\s*(.*)$/.exec(line);

    if (dashMatch) {
      var dashIndent = dashMatch[1].length;
      if (itemIndent < 0) itemIndent = dashIndent;
      if (dashIndent < itemIndent) break; // dedented past the list -- done
      if (dashIndent > keyIndent && current !== null && dashIndent === itemIndent) {
        items.push(current);
      }
      current = {};
      current[dashMatch[2]] = unquote(dashMatch[3]);
      continue;
    }

    var contMatch = /^(\s*)([A-Za-z_][\w]*):\s*(.*)$/.exec(line);
    if (contMatch && current !== null && indent > itemIndent) {
      current[contMatch[2]] = unquote(contMatch[3]);
      continue;
    }

    // Anything else at indent <= keyIndent means we've left the list
    // (e.g. the next top-level "time_window:" key).
    if (indent <= keyIndent) break;
  }
  if (current !== null) items.push(current);
  return items;
}

function unquote(v) {
  v = v.trim();
  if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') {
    return v.slice(1, -1);
  }
  return v;
}

// All systems in this lab are Windows -- a real multi-OS lab would need a
// fuller map, not built here since nothing in attack.yaml exercises it.
function osType(osName) {
  return /^windows/i.test(osName || '') ? 'windows' : undefined;
}

function emailDomain(users) {
  for (var i = 0; i < users.length; i++) {
    var email = users[i].email;
    if (email && email.indexOf('@') >= 0) {
      return email.slice(email.indexOf('@') + 1);
    }
  }
  throw new Error('no user with an email address found in attack.yaml -- cannot derive the FQDN domain');
}

var CSV_HEADER = ['host.name', 'host.hostname', 'host.ip', 'host.os.name', 'host.os.type', 'host.os.family', 'host.type', 'asset.owner'];

function csvEscape(v) {
  v = v == null ? '' : String(v);
  if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}

function buildCsv() {
  var text = fs.readFileSync(ATTACK_YAML, 'utf8');
  var users = parseYamlList(text, 'users');
  var systems = parseYamlList(text, 'systems');
  var domain = emailDomain(users);

  var rows = [CSV_HEADER];
  systems.forEach(function (sys) {
    var shortName = sys.hostname;
    var fqdn = shortName + '.' + domain;
    var type = osType(sys.os);
    var row = [
      null, // host.name -- filled in per-row below
      shortName,
      sys.ip || '',
      sys.os || '',
      type || '',
      type || '', // host.os.family: same as type for this lab (all Windows)
      sys.type || '',
      sys.assigned_user || ''
    ];
    // Emit both the short name and the FQDN as separate rows keyed on
    // host.name so the lookup matches regardless of which form an event
    // carries -- the pipeline always sets host.name to the FQDN today, but
    // this is defensive against that changing.
    rows.push([shortName].concat(row.slice(1)));
    rows.push([fqdn].concat(row.slice(1)));
  });

  return rows.map(function (r) { return r.map(csvEscape).join(','); }).join('\n') + '\n';
}

function main() {
  var check = process.argv.indexOf('--check') !== -1;
  var next = buildCsv();

  var current = null;
  try {
    current = fs.readFileSync(CSV_OUT, 'utf8');
  } catch (e) {
    // file doesn't exist yet -- current stays null
  }

  if (current === next) {
    console.log('forge-assets.csv is up to date with attack.yaml');
    return;
  }
  if (check) {
    console.error('STALE: forge-assets.csv does not match eforge/attack.yaml');
    console.error('Run: node cribl/generate-assets-lookup.js');
    process.exit(1);
  }

  fs.mkdirSync(path.dirname(CSV_OUT), { recursive: true });
  fs.writeFileSync(CSV_OUT, next);
  console.log('wrote ' + CSV_OUT + ' (' + (next.split('\n').length - 1) + ' rows)');
}

main();
