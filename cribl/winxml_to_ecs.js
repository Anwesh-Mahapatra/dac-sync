'use strict';

// Parses a single Windows Event XML <Event>...</Event> chunk (as produced by
// forge-winxml.breaker.json) and maps it onto ECS fields, preserving the raw
// EventData under winlog.event_data.* -- the same namespace winlogbeat uses.
//
// This file is the single source of truth: forge_win_ecs.pipeline.json embeds
// applyToEvent.toString() verbatim as its Code function body (see
// generate-pipeline.js), so testing this file IS testing what runs in Cribl.

function unescapeXml(s) {
  if (s == null) return s;
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function hexToDecimal(hex) {
  if (!hex) return undefined;
  if (/^0x/i.test(hex)) return parseInt(hex, 16);
  var n = parseInt(hex, 10);
  return isNaN(n) ? undefined : n;
}

function basename(path) {
  if (!path) return undefined;
  var parts = path.split(/[\\/]/);
  return parts[parts.length - 1];
}

function stripIpv4Mapped(ip) {
  if (!ip) return ip;
  return ip.replace(/^::ffff:/i, '');
}

// Tokenizes a Windows command line into an argv-style array, treating a run
// of characters wrapped in matching '"' or "'" as one token (quotes of the
// other kind are kept literal inside), same as a simple shell-style split.
function splitArgs(cmdline) {
  if (!cmdline) return [];
  var args = [];
  var current = '';
  var quoteChar = null;
  for (var i = 0; i < cmdline.length; i++) {
    var ch = cmdline[i];
    if (quoteChar) {
      if (ch === quoteChar) {
        quoteChar = null;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      quoteChar = ch;
    } else if (/\s/.test(ch)) {
      if (current.length > 0) {
        args.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) args.push(current);
  return args;
}

function extractEventData(xml) {
  var data = {};
  var re = /<Data Name="([^"]+)">([\s\S]*?)<\/Data>/g;
  var m;
  while ((m = re.exec(xml)) !== null) {
    data[m[1]] = unescapeXml(m[2]);
  }
  // Self-closing <Data Name="X"/> (empty value) -- not seen in EvidenceForge
  // output but valid per the Windows Event schema.
  var reEmpty = /<Data Name="([^"]+)"\s*\/>/g;
  while ((m = reEmpty.exec(xml)) !== null) {
    if (!(m[1] in data)) data[m[1]] = '';
  }
  return data;
}

// function (__e) -- this exact signature is what Cribl's Code function
// expects (see cribl/functions/code/conf.ui-schema.json placeholder).
function applyToEvent(__e) {
  var raw = __e._raw;
  // Cribl's Code function forbids top-level "return" in submitted code (it
  // wraps the string as the body of its own exports.process(__e), and the
  // validator statically rejects "return" outside a function declaration
  // even though it would work fine at runtime) -- so guard with nested ifs
  // instead of early returns.
  if (raw) {
  var eventMatch = /<Event[\s\S]*?<\/Event>/.exec(raw);
  if (eventMatch) {
  var xml = eventMatch[0];

  var eventIdMatch = /<EventID>(\d+)<\/EventID>/.exec(xml);
  if (eventIdMatch) {
  var eventId = eventIdMatch[1];

  var providerMatch = /<Provider Name="([^"]*)"/.exec(xml);
  var timeMatch = /<TimeCreated SystemTime="([^"]*)"/.exec(xml);
  var computerMatch = /<Computer>([^<]*)<\/Computer>/.exec(xml);
  var channelMatch = /<Channel>([^<]*)<\/Channel>/.exec(xml);
  var recordIdMatch = /<EventRecordID>(\d+)<\/EventRecordID>/.exec(xml);

  var eventData = extractEventData(xml);

  if (timeMatch) {
    var d = new Date(timeMatch[1]);
    if (!isNaN(d.getTime())) {
      __e._time = d.getTime() / 1000;
    }
  }

  __e.event = __e.event || {};
  __e.event.code = eventId;
  if (providerMatch) __e.event.provider = providerMatch[1];

  if (computerMatch) __e.host = computerMatch[1];

  __e.winlog = __e.winlog || {};
  __e.winlog.event_id = parseInt(eventId, 10);
  if (channelMatch) __e.winlog.channel = channelMatch[1];
  if (computerMatch) __e.winlog.computer_name = computerMatch[1];
  if (recordIdMatch) __e.winlog.record_id = recordIdMatch[1];
  __e.winlog.event_data = eventData;

  // Cribl's Filesystem Collector sets a built-in top-level "source" field to
  // the originating file path -- the same field the route filter matches on
  // (source.endsWith('windows_event_security.xml')). The ECS mapping below
  // needs "source" too (source.ip/source.port), which would silently
  // clobber the file path before a later function could read it. Capture it
  // here, first, while it's still pristine, then clear it -- if this event
  // type sets source.ip below it gets reassigned; if not, "source" must not
  // linger as the stale file-path string (the eval function only removes
  // _raw now, not "source", since by eval-time "source" may legitimately be
  // this function's own ECS source.ip/source.port object).
  __e.log = __e.log || {};
  __e.log.file = __e.log.file || {};
  __e.log.file.path = __e.source;
  delete __e.source;

  switch (eventId) {
    case '4688': { // process creation
      var proc = {
        pid: hexToDecimal(eventData.NewProcessId),
        executable: eventData.NewProcessName,
        name: basename(eventData.NewProcessName),
        command_line: eventData.CommandLine,
        args: splitArgs(eventData.CommandLine)
      };
      var parentPid = hexToDecimal(eventData.ProcessId);
      proc.parent = {};
      if (parentPid !== undefined) proc.parent.pid = parentPid;
      if (eventData.ParentProcessName) {
        proc.parent.executable = eventData.ParentProcessName;
        proc.parent.name = basename(eventData.ParentProcessName);
      }
      __e.process = proc;
      __e.user = {
        name: eventData.SubjectUserName,
        domain: eventData.SubjectDomainName,
        id: eventData.SubjectUserSid
      };
      break;
    }
    case '4624': // successful logon
    case '4625': { // failed logon
      __e.user = {
        name: eventData.TargetUserName,
        domain: eventData.TargetDomainName,
        id: eventData.TargetUserSid
      };
      __e.event.outcome = (eventId === '4624') ? 'success' : 'failure';
      __e.winlog.logon = { type: eventData.LogonType };
      if (eventData.IpAddress && eventData.IpAddress !== '-') {
        __e.source = { ip: stripIpv4Mapped(eventData.IpAddress) };
        if (eventData.IpPort && eventData.IpPort !== '-') {
          __e.source.port = parseInt(eventData.IpPort, 10);
        }
      }
      if (eventData.ProcessName) {
        __e.process = {
          executable: eventData.ProcessName,
          name: basename(eventData.ProcessName)
        };
        var logonPid = hexToDecimal(eventData.ProcessId);
        if (logonPid !== undefined) __e.process.pid = logonPid;
      }
      break;
    }
    case '4648': { // explicit credential logon -- lateral movement
      __e.user = {
        name: eventData.TargetUserName,
        domain: eventData.TargetDomainName
      };
      __e.destination = { domain: eventData.TargetDomainName };
      if (eventData.TargetServerName) __e.destination.address = eventData.TargetServerName;
      if (eventData.IpAddress && eventData.IpAddress !== '-') {
        __e.source = { ip: stripIpv4Mapped(eventData.IpAddress) };
        if (eventData.IpPort && eventData.IpPort !== '-') {
          __e.source.port = parseInt(eventData.IpPort, 10);
        }
      }
      break;
    }
    default:
      break;
  }
  }
  }
  }
}

module.exports = {
  applyToEvent: applyToEvent,
  splitArgs: splitArgs,
  stripIpv4Mapped: stripIpv4Mapped,
  hexToDecimal: hexToDecimal,
  basename: basename,
  unescapeXml: unescapeXml,
  extractEventData: extractEventData
};

if (require.main === module) {
  var assert = require('assert');
  var failures = 0;

  function test(name, fn) {
    try {
      fn();
      console.log('PASS: ' + name);
    } catch (e) {
      failures++;
      console.log('FAIL: ' + name);
      console.log('  ' + e.message);
    }
  }

  // Real samples pulled from eforge/output/data/*/windows_event_security.xml

  var SAMPLE_4688_ENCODED_PS =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    <EventID>4688</EventID>\n' +
    '    <TimeCreated SystemTime="2026-07-13T05:11:03.0000000Z"/>\n' +
    '    <EventRecordID>349999</EventRecordID>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-ANALYST-01.corp.example.com</Computer>\n' +
    '  </System>\n' +
    '  <EventData>\n' +
    '    <Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data>\n' +
    '    <Data Name="SubjectUserName">jsmith</Data>\n' +
    '    <Data Name="SubjectDomainName">CORP</Data>\n' +
    '    <Data Name="NewProcessId">0x1a2c</Data>\n' +
    '    <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>\n' +
    '    <Data Name="ProcessId">0xe88</Data>\n' +
    '    <Data Name="CommandLine">powershell.exe -enc JABkAGMAID0A</Data>\n' +
    '    <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>\n' +
    '  </EventData>\n' +
    '</Event>\n';

  var SAMPLE_4688_QUOTED_ARGS =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    <EventID>4688</EventID>\n' +
    '    <TimeCreated SystemTime="2026-07-13T06:05:39.0000000Z"/>\n' +
    '    <EventRecordID>350010</EventRecordID>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>SRV-DC-01.corp.example.com</Computer>\n' +
    '  </System>\n' +
    '  <EventData>\n' +
    '    <Data Name="SubjectUserSid">S-1-5-21-1-2-3-1003</Data>\n' +
    '    <Data Name="SubjectUserName">attacker</Data>\n' +
    '    <Data Name="SubjectDomainName">CORP</Data>\n' +
    '    <Data Name="NewProcessId">0x22b0</Data>\n' +
    '    <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>\n' +
    '    <Data Name="ProcessId">0x9f4</Data>\n' +
    '    <Data Name="CommandLine">powershell.exe -Command "Import-Module .\\PowerView.ps1; Get-DomainUser -LDAPFilter \'(adminCount=1)\'"</Data>\n' +
    '  </EventData>\n' +
    '</Event>\n';

  var SAMPLE_4688_ESCAPED_AMPERSAND =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    <EventID>4688</EventID>\n' +
    '    <TimeCreated SystemTime="2026-07-13T05:20:00.0000000Z"/>\n' +
    '    <EventRecordID>350020</EventRecordID>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-EXEC-01.corp.example.com</Computer>\n' +
    '  </System>\n' +
    '  <EventData>\n' +
    '    <Data Name="SubjectUserSid">S-1-5-21-1-2-3-1002</Data>\n' +
    '    <Data Name="SubjectUserName">mjones</Data>\n' +
    '    <Data Name="SubjectDomainName">CORP</Data>\n' +
    '    <Data Name="NewProcessId">0x3af0</Data>\n' +
    '    <Data Name="NewProcessName">C:\\Users\\attacker\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe</Data>\n' +
    '    <Data Name="ProcessId">0x100</Data>\n' +
    '    <Data Name="CommandLine">"C:\\Users\\attacker\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe" --url=zoommtg://zoom.us/join?action=join&amp;confno=2048</Data>\n' +
    '  </EventData>\n' +
    '</Event>\n';

  var SAMPLE_4624 =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    <EventID>4624</EventID>\n' +
    '    <TimeCreated SystemTime="2026-07-13T05:05:37.8324849Z"/>\n' +
    '    <EventRecordID>349878</EventRecordID>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-ANALYST-01.corp.example.com</Computer>\n' +
    '  </System>\n' +
    '  <EventData>\n' +
    '    <Data Name="SubjectUserSid">S-1-5-18</Data>\n' +
    '    <Data Name="SubjectUserName">SYSTEM</Data>\n' +
    '    <Data Name="SubjectDomainName">NT AUTHORITY</Data>\n' +
    '    <Data Name="TargetUserSid">S-1-5-21-2684217973-1604675485-2509691772-1003</Data>\n' +
    '    <Data Name="TargetUserName">attacker</Data>\n' +
    '    <Data Name="TargetDomainName">CORP</Data>\n' +
    '    <Data Name="LogonType">3</Data>\n' +
    '    <Data Name="ProcessId">0xe70</Data>\n' +
    '    <Data Name="ProcessName">C:\\Windows\\System32\\lsass.exe</Data>\n' +
    '    <Data Name="IpAddress">::ffff:203.0.113.50</Data>\n' +
    '    <Data Name="IpPort">50958</Data>\n' +
    '  </EventData>\n' +
    '</Event>\n';

  var SAMPLE_4625_NO_SOURCE_IP =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    <EventID>4625</EventID>\n' +
    '    <TimeCreated SystemTime="2026-07-13T06:22:10.9495224Z"/>\n' +
    '    <EventRecordID>666855</EventRecordID>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-EXEC-01.corp.example.com</Computer>\n' +
    '  </System>\n' +
    '  <EventData>\n' +
    '    <Data Name="SubjectUserSid">S-1-0-0</Data>\n' +
    '    <Data Name="SubjectUserName">-</Data>\n' +
    '    <Data Name="TargetUserSid">S-1-5-21-2684217973-1604675485-2509691772-1002</Data>\n' +
    '    <Data Name="TargetUserName">mjones</Data>\n' +
    '    <Data Name="TargetDomainName">CORP</Data>\n' +
    '    <Data Name="LogonType">2</Data>\n' +
    '    <Data Name="ProcessId">0x107c</Data>\n' +
    '    <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data>\n' +
    '    <Data Name="IpAddress">-</Data>\n' +
    '    <Data Name="IpPort">-</Data>\n' +
    '  </EventData>\n' +
    '</Event>\n';

  var SAMPLE_4648_LATERAL =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    <EventID>4648</EventID>\n' +
    '    <TimeCreated SystemTime="2026-07-13T05:35:33.0000000Z"/>\n' +
    '    <EventRecordID>350030</EventRecordID>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-ANALYST-01.corp.example.com</Computer>\n' +
    '  </System>\n' +
    '  <EventData>\n' +
    '    <Data Name="SubjectUserName">jsmith</Data>\n' +
    '    <Data Name="SubjectDomainName">CORP</Data>\n' +
    '    <Data Name="TargetUserName">administrator</Data>\n' +
    '    <Data Name="TargetDomainName">CORP</Data>\n' +
    '    <Data Name="TargetServerName">WS-EXEC-01.corp.example.com</Data>\n' +
    '    <Data Name="ProcessName">C:\\Windows\\System32\\cmd.exe</Data>\n' +
    '    <Data Name="IpAddress">10.0.10.50</Data>\n' +
    '    <Data Name="IpPort">0</Data>\n' +
    '  </EventData>\n' +
    '</Event>\n';

  // A wrapper chunk like the drop function is meant to kill: the file
  // preamble before the first <Event> match.
  var SAMPLE_WRAPPER = '<?xml version="1.0" encoding="utf-8"?>\n<Events>\n';

  test('4688 encoded PowerShell: decodes hex PID, sets process.args', function () {
    var e = { _raw: SAMPLE_4688_ENCODED_PS };
    applyToEvent(e);
    assert.strictEqual(e.event.code, '4688');
    assert.strictEqual(e.process.pid, 0x1a2c);
    assert.strictEqual(e.process.pid, 6700);
    assert.strictEqual(e.process.parent.pid, 0xe88);
    assert.strictEqual(e.process.name, 'powershell.exe');
    assert.strictEqual(e.process.command_line, 'powershell.exe -enc JABkAGMAID0A');
    assert.deepStrictEqual(e.process.args, ['powershell.exe', '-enc', 'JABkAGMAID0A']);
    assert.strictEqual(e.process.parent.name, 'cmd.exe');
    assert.strictEqual(e.winlog.event_data.CommandLine, 'powershell.exe -enc JABkAGMAID0A');
    assert.ok(e._time > 0, '_time should be set from TimeCreated');
  });

  test('4688 with mixed quote styles: outer double-quotes group the -Command arg, inner single quotes stay literal', function () {
    var e = { _raw: SAMPLE_4688_QUOTED_ARGS };
    applyToEvent(e);
    assert.deepStrictEqual(e.process.args, [
      'powershell.exe',
      '-Command',
      "Import-Module .\\PowerView.ps1; Get-DomainUser -LDAPFilter '(adminCount=1)'"
    ]);
  });

  test('4688 with XML-escaped ampersand: &amp; is unescaped in command_line and args', function () {
    var e = { _raw: SAMPLE_4688_ESCAPED_AMPERSAND };
    applyToEvent(e);
    assert.ok(e.process.command_line.indexOf('&amp;') === -1, 'raw &amp; must not survive unescaping');
    assert.ok(e.process.command_line.indexOf('join&confno') !== -1, 'unescaped & must be present');
    assert.deepStrictEqual(e.process.args, [
      'C:\\Users\\attacker\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe',
      '--url=zoommtg://zoom.us/join?action=join&confno=2048'
    ]);
  });

  test('4688 (no network source): the original file-path "source" is cleared, not left dangling as a stale string', function () {
    var e = { _raw: SAMPLE_4688_ENCODED_PS, source: '/data/eforge/WS-ANALYST-01.corp.example.com/windows_event_security.xml' };
    applyToEvent(e);
    assert.strictEqual(e.log.file.path, '/data/eforge/WS-ANALYST-01.corp.example.com/windows_event_security.xml');
    assert.strictEqual(e.source, undefined, 'source must not linger as the pre-ECS file-path string once captured into log.file.path');
  });

  test('4624: source.ip is set AND stripped of the ::ffff: IPv4-mapped prefix, source.port set, log.file.path preserved despite the source-field collision', function () {
    // Cribl's Filesystem Collector sets a built-in top-level "source" field
    // to the file path (same field the route filter matches on). Simulate
    // that pre-existing value to prove it survives into log.file.path
    // instead of being silently clobbered by the ECS source.ip/source.port
    // object this function also writes to "source".
    var e = { _raw: SAMPLE_4624, source: '/data/eforge/WS-ANALYST-01.corp.example.com/windows_event_security.xml' };
    applyToEvent(e);
    assert.strictEqual(e.event.code, '4624');
    assert.strictEqual(e.event.outcome, 'success');
    assert.strictEqual(e.log.file.path, '/data/eforge/WS-ANALYST-01.corp.example.com/windows_event_security.xml', 'log.file.path must capture the original source before it gets overwritten');
    // Explicit, not just "truthy" -- confirms the field exists and has the
    // exact expected value, not a leftover ::ffff:-prefixed one.
    assert.strictEqual(typeof e.source, 'object', 'source object must exist on 4624');
    assert.strictEqual(e.source.ip, '203.0.113.50');
    assert.notStrictEqual(e.source.ip, '::ffff:203.0.113.50');
    assert.ok(e.source.ip.indexOf('::ffff:') === -1, 'source.ip must not retain the IPv4-mapped prefix');
    assert.strictEqual(e.source.port, 50958);
    assert.strictEqual(e.user.name, 'attacker');
    assert.strictEqual(e.winlog.logon.type, '3');
  });

  test('4625 with IpAddress "-": source.ip is NOT set (no bogus "-" value)', function () {
    var e = { _raw: SAMPLE_4625_NO_SOURCE_IP };
    applyToEvent(e);
    assert.strictEqual(e.event.outcome, 'failure');
    assert.strictEqual(e.source, undefined);
    assert.strictEqual(e.user.name, 'mjones');
  });

  test('4648 lateral movement: destination.domain set from TargetDomainName', function () {
    var e = { _raw: SAMPLE_4648_LATERAL };
    applyToEvent(e);
    assert.strictEqual(e.destination.domain, 'CORP');
    assert.strictEqual(e.destination.address, 'WS-EXEC-01.corp.example.com');
    assert.strictEqual(e.source.ip, '10.0.10.50');
  });

  test('wrapper chunk (no <Event>) is left untouched -- caller is expected to drop it', function () {
    var e = { _raw: SAMPLE_WRAPPER };
    applyToEvent(e);
    assert.strictEqual(e.event, undefined);
  });

  test('trailing </Events> after the last <Event> does not corrupt parsing', function () {
    var e = { _raw: SAMPLE_4624 + '</Events>\n' };
    applyToEvent(e);
    assert.strictEqual(e.source.ip, '203.0.113.50');
  });

  test('winlog.event_data.* preserves the full raw EventData map', function () {
    var e = { _raw: SAMPLE_4624 };
    applyToEvent(e);
    assert.strictEqual(e.winlog.event_data.TargetUserSid, 'S-1-5-21-2684217973-1604675485-2509691772-1003');
    assert.strictEqual(e.winlog.event_data.IpAddress, '::ffff:203.0.113.50', 'raw winlog.event_data.IpAddress keeps the original unstripped value');
  });

  console.log('');
  if (failures > 0) {
    console.log(failures + ' test(s) failed.');
    process.exit(1);
  } else {
    console.log('All tests passed.');
  }
}
