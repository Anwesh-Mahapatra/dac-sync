'use strict';

// Replays the EvidenceForge XML through the SAME applyToEvent() that Cribl runs
// (cribl/winxml_to_ecs.js) and bulk-indexes the result into a fresh index built
// from cribl/forge-windows-ecs.index-template.json.
//
//   ES_PASS=... node es/load-forge.js [--index forge-windows-ecs-000001] [--recreate]
//
// Why this exists: Cribl's Filesystem Collector is only routed at
// windows_event_security.xml, so the 993 Sysmon events never reached ES at all.
// Rather than hand-drive Cribl's API, this replays both channels through the
// tested mapping function, which is also what makes the detection rules
// testable against real attack data.
//
// It writes ONLY to the target index and never touches winlogbeat-* or the
// legacy forge-windows-ecs index.

var fs = require('fs');
var path = require('path');
var http = require('http');
var ecs = require('../cribl/winxml_to_ecs.js');

var ES_URL = process.env.ES_URL || 'http://localhost:9200';
var ES_USER = process.env.ES_USER || 'elastic';
var ES_PASS = process.env.ES_PASS || process.env.ELASTIC_PASSWORD;

var argv = process.argv.slice(2);
function flag(name, dflt) {
  var i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
}
var INDEX = flag('--index', 'forge-windows-ecs-000001');
var RECREATE = argv.indexOf('--recreate') >= 0;

if (!ES_PASS) {
  console.error('error: set ES_PASS or ELASTIC_PASSWORD');
  process.exit(1);
}

function es(method, urlPath, body, contentType) {
  return new Promise(function (resolve, reject) {
    var u = new URL(ES_URL + urlPath);
    var req = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method: method,
      auth: ES_USER + ':' + ES_PASS,
      headers: { 'Content-Type': contentType || 'application/json' }
    }, function (res) {
      var chunks = '';
      res.on('data', function (d) { chunks += d; });
      res.on('end', function () {
        var parsed;
        try { parsed = JSON.parse(chunks); } catch (e) { parsed = { raw: chunks }; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Mirrors what Cribl's Elastic destination does with the event before shipping:
// _time becomes @timestamp, and Cribl internals never reach _source.
function toDoc(event) {
  if (typeof event._time === 'number') {
    event['@timestamp'] = new Date(event._time * 1000).toISOString();
  }
  // Cribl's built-in "host" is a plain string; ECS wants host.name.
  if (typeof event.host === 'string') {
    event.host = { name: event.host };
  }
  delete event._raw;
  delete event._time;
  delete event.filter_path; // P4: must never reach _source
  event.ecs = { version: '8.0.0' };
  return event;
}

function eventsFromFile(file) {
  var xml = fs.readFileSync(file, 'utf8');
  var out = [];
  var re = /<Event[\s\S]*?<\/Event>/g;
  var m;
  while ((m = re.exec(xml)) !== null) {
    var e = { _raw: m[0], source: file };
    ecs.applyToEvent(e);
    if (e.event && e.event.code) out.push(toDoc(e));
  }
  return out;
}

async function main() {
  var dataDir = path.join(__dirname, '..', 'eforge', 'output', 'data');
  var files = [];
  fs.readdirSync(dataDir).forEach(function (host) {
    var hostDir = path.join(dataDir, host);
    if (!fs.statSync(hostDir).isDirectory()) return;
    fs.readdirSync(hostDir).forEach(function (f) {
      if (f.endsWith('.xml')) files.push(path.join(hostDir, f));
    });
  });

  if (RECREATE) {
    var del = await es('DELETE', '/' + INDEX);
    console.log('deleted ' + INDEX + ' (status ' + del.status + ')');
  }

  var created = await es('PUT', '/' + INDEX, '{}');
  if (created.status >= 400 && created.body.error &&
      created.body.error.type !== 'resource_already_exists_exception') {
    console.error('failed to create index:', JSON.stringify(created.body.error));
    process.exit(1);
  }
  console.log('target index: ' + INDEX + ' (from template forge-windows-ecs)');

  var total = 0;
  var byCode = {};
  for (var i = 0; i < files.length; i++) {
    var docs = eventsFromFile(files[i]);
    var lines = [];
    docs.forEach(function (d) {
      byCode[d.event.code] = (byCode[d.event.code] || 0) + 1;
      lines.push(JSON.stringify({ index: { _index: INDEX } }));
      lines.push(JSON.stringify(d));
    });
    if (!lines.length) continue;

    var res = await es('POST', '/_bulk?refresh=true', lines.join('\n') + '\n',
                       'application/x-ndjson');
    if (res.body.errors) {
      var firstErr = res.body.items.filter(function (it) { return it.index.error; })[0];
      console.error('bulk errors in ' + files[i] + ':',
                    JSON.stringify(firstErr.index.error));
      process.exit(1);
    }
    total += docs.length;
    console.log('  ' + path.basename(path.dirname(files[i])) + '/' +
                path.basename(files[i]) + ': ' + docs.length + ' events');
  }

  console.log('\nindexed ' + total + ' events into ' + INDEX);
  console.log('by event.code: ' + JSON.stringify(byCode));
}

main().catch(function (e) { console.error(e); process.exit(1); });
