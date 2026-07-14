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

// 5156/5157 addresses can legitimately be "-" (no address) or a literal "::"
// (unspecified IPv6) -- neither is a real address worth indexing as `ip`.
function validAddr(v) {
  return !!v && v !== '-' && v !== '::';
}

// 5156/5157 Direction is a Windows "resource string" code, not a plain word.
// Accept the raw %% codes we've actually observed, and the literal words too
// in case a future EvidenceForge version writes them out directly.
function networkDirection(v) {
  if (!v) return undefined;
  if (v === '%%14592') return 'inbound';
  if (v === '%%14593') return 'outbound';
  var lower = v.toLowerCase();
  if (lower === 'inbound' || lower === 'outbound') return lower;
  return undefined;
}

// 5156/5157 Protocol is a numeric IANA protocol number (e.g. "6", "17"), not
// the lowercase word Sysmon 3 gives you -- do NOT .toLowerCase() this.
function ianaProtoName(v) {
  if (v == null) return undefined;
  switch (parseInt(v, 10)) {
    case 1: return 'icmp';
    case 6: return 'tcp';
    case 17: return 'udp';
    case 58: return 'ipv6-icmp';
    default: return v;
  }
}

// 5156/5157 Application is a device path (\device\harddiskvolumeN\...), which
// won't join against 4688's drive-letter process.executable unless normalized.
// ASSUMPTION: volume 1 = C: -- this lab has one disk. Any other volume number
// is left unnormalized (still indexed, just not join-able with 4688).
function normalizeDevicePath(p) {
  if (!p) return p;
  var m = /^\\device\\harddiskvolume(\d+)\\(.*)$/i.exec(p);
  if (!m || m[1] !== '1') return p;
  return 'C:\\' + m[2];
}

// event.dataset per winlog.channel. Fallback covers channels we don't have a
// specific mapping for yet.
var EVENT_DATASET_BY_CHANNEL = {
  'Security': 'windows.security',
  'Microsoft-Windows-Sysmon/Operational': 'windows.sysmon_operational',
  'System': 'windows.system'
};
function eventDataset(channel) {
  return EVENT_DATASET_BY_CHANNEL[channel] || 'windows.other';
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

// Sysmon writes a literal "-" for fields it has no value for (OriginalFileName,
// FileVersion, Hashes on an unsigned binary, ...). Treat it as absent so we
// don't index "-" as if it were a real process name or hash.
function sysmonVal(v) {
  if (v == null) return undefined;
  if (v === '' || v === '-') return undefined;
  return v;
}

// Sysmon's User is "DOMAIN\user" (e.g. "CORP\attacker"). Security events carry
// the domain and user in separate <Data> elements, so this split is Sysmon-only.
function splitDomainUser(v) {
  var s = sysmonVal(v);
  if (!s) return undefined;
  var i = s.indexOf('\\');
  if (i < 0) return { name: s };
  return { domain: s.slice(0, i), name: s.slice(i + 1) };
}

// Sysmon's Hashes is a flat CSV of ALGO=hex pairs, e.g.
// "SHA1=A1B2...,MD5=C3D4...,SHA256=E5F6...,IMPHASH=0011...". ECS wants them
// under process.hash.<algo> (lowercased); IMPHASH belongs to process.pe.imphash.
function parseHashes(v) {
  var s = sysmonVal(v);
  if (!s) return undefined;
  var out = {};
  var parts = s.split(',');
  for (var i = 0; i < parts.length; i++) {
    var kv = parts[i].split('=');
    if (kv.length !== 2) continue;
    var algo = kv[0].trim().toLowerCase();
    var val = kv[1].trim();
    if (val) out[algo] = val;
  }
  return Object.keys(out).length ? out : undefined;
}

// Builds the ECS process.* object shared by every Sysmon event that names an
// Image. Sysmon ProcessId is already decimal (Security's is hex) -- hexToDecimal
// handles both.
function sysmonProcess(eventData) {
  var proc = {};
  var image = sysmonVal(eventData.Image);
  if (image) {
    proc.executable = image;
    proc.name = basename(image);
  }
  var pid = hexToDecimal(sysmonVal(eventData.ProcessId));
  if (pid !== undefined) proc.pid = pid;
  var guid = sysmonVal(eventData.ProcessGuid);
  if (guid) proc.entity_id = guid;
  return proc;
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
  __e.event.kind = 'event';
  __e.event.module = 'windows';
  __e.event.dataset = eventDataset(channelMatch ? channelMatch[1] : undefined);
  if (providerMatch) __e.event.provider = providerMatch[1];

  if (computerMatch) {
    __e.host = { name: computerMatch[1], hostname: computerMatch[1].split('.')[0] };
  }

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

  // Sysmon EIDs (1, 3, 11, ...) are small integers that collide with EIDs on
  // other channels (System EID 1 is not a process creation). Only treat them as
  // Sysmon when the provider says so.
  var isSysmon = !!providerMatch && providerMatch[1].indexOf('Sysmon') >= 0;

  switch (eventId) {
    case '1': { // Sysmon: process creation
      if (isSysmon) {
        var sProc = sysmonProcess(eventData);
        sProc.command_line = sysmonVal(eventData.CommandLine);
        sProc.args = splitArgs(sysmonVal(eventData.CommandLine));
        sProc.working_directory = sysmonVal(eventData.CurrentDirectory);

        var origName = sysmonVal(eventData.OriginalFileName);
        var product = sysmonVal(eventData.Product);
        var company = sysmonVal(eventData.Company);
        var fileVer = sysmonVal(eventData.FileVersion);
        var descr = sysmonVal(eventData.Description);
        var hashes = parseHashes(eventData.Hashes);
        // OriginalFileName is the name compiled into the PE header -- it does not
        // change when the file on disk is renamed, so it is the rename-evasion
        // signal. ECS files it under process.pe.original_file_name.
        if (origName || product || company || fileVer || descr) {
          sProc.pe = {};
          if (origName) sProc.pe.original_file_name = origName;
          if (product) sProc.pe.product = product;
          if (company) sProc.pe.company = company;
          if (fileVer) sProc.pe.file_version = fileVer;
          if (descr) sProc.pe.description = descr;
        }
        if (hashes) {
          if (hashes.imphash) {
            sProc.pe = sProc.pe || {};
            sProc.pe.imphash = hashes.imphash;
            delete hashes.imphash;
          }
          if (Object.keys(hashes).length) sProc.hash = hashes;
        }

        var pImage = sysmonVal(eventData.ParentImage);
        var pCmd = sysmonVal(eventData.ParentCommandLine);
        var pPid = hexToDecimal(sysmonVal(eventData.ParentProcessId));
        var pGuid = sysmonVal(eventData.ParentProcessGuid);
        if (pImage || pCmd || pPid !== undefined || pGuid) {
          sProc.parent = {};
          if (pImage) {
            sProc.parent.executable = pImage;
            sProc.parent.name = basename(pImage);
          }
          if (pCmd) {
            sProc.parent.command_line = pCmd;
            sProc.parent.args = splitArgs(pCmd);
          }
          if (pPid !== undefined) sProc.parent.pid = pPid;
          if (pGuid) sProc.parent.entity_id = pGuid;
        }

        __e.process = sProc;
        var sUser = splitDomainUser(eventData.User);
        if (sUser) __e.user = sUser;
        __e.event.category = ['process'];
        __e.event.type = ['start'];
      }
      break;
    }
    case '3': { // Sysmon: network connection
      if (isSysmon) {
        __e.process = sysmonProcess(eventData);
        var nUser = splitDomainUser(eventData.User);
        if (nUser) __e.user = nUser;

        var srcIp = sysmonVal(eventData.SourceIp);
        if (srcIp) {
          __e.source = { ip: stripIpv4Mapped(srcIp) };
          var srcPort = parseInt(sysmonVal(eventData.SourcePort), 10);
          if (!isNaN(srcPort)) __e.source.port = srcPort;
        }
        var dstIp = sysmonVal(eventData.DestinationIp);
        if (dstIp) {
          __e.destination = { ip: stripIpv4Mapped(dstIp) };
          var dstPort = parseInt(sysmonVal(eventData.DestinationPort), 10);
          if (!isNaN(dstPort)) __e.destination.port = dstPort;
        }
        // DestinationHostname is a resolved name, which is ECS destination.domain.
        var dstHost = sysmonVal(eventData.DestinationHostname);
        if (dstHost) {
          __e.destination = __e.destination || {};
          __e.destination.domain = dstHost;
        }
        var transportProtocol = sysmonVal(eventData.Protocol);
        if (transportProtocol) {
          __e.network = { transport: transportProtocol.toLowerCase() };
      }     

        __e.event.category = ['network'];
        __e.event.type = ['connection'];
      }
      break;
    }
    case '11': { // Sysmon: file created
      if (isSysmon) {
        __e.process = sysmonProcess(eventData);
        var fUser = splitDomainUser(eventData.User);
        if (fUser) __e.user = fUser;

        var target = sysmonVal(eventData.TargetFilename);
        if (target) {
          __e.file = { path: target, name: basename(target) };
          var sep = Math.max(target.lastIndexOf('\\'), target.lastIndexOf('/'));
          if (sep > 0) __e.file.directory = target.slice(0, sep);
        }
        __e.event.category = ['file'];
        __e.event.type = ['creation'];
      }
      break;
    }
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
      __e.event.category = ['process'];
      __e.event.type = ['start'];
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
      __e.event.category = ['authentication'];
      __e.event.type = ['start'];
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
    case '5156': // Windows Filtering Platform: connection allowed
    case '5157': { // Windows Filtering Platform: connection blocked
      var allowed = (eventId === '5156');

      if (validAddr(eventData.SourceAddress)) {
        __e.source = { ip: stripIpv4Mapped(eventData.SourceAddress) };
        var wfpSrcPort = parseInt(eventData.SourcePort, 10);
        if (!isNaN(wfpSrcPort)) __e.source.port = wfpSrcPort;
      }
      if (validAddr(eventData.DestAddress)) {
        __e.destination = { ip: stripIpv4Mapped(eventData.DestAddress) };
        var wfpDstPort = parseInt(eventData.DestPort, 10);
        if (!isNaN(wfpDstPort)) __e.destination.port = wfpDstPort;
      }

      var proto = ianaProtoName(eventData.Protocol);
      if (proto) __e.network = { transport: proto };
      var direction = networkDirection(eventData.Direction);
      if (direction) {
        __e.network = __e.network || {};
        __e.network.direction = direction;
      }

      if (eventData.Application) {
        var appPath = normalizeDevicePath(eventData.Application);
        __e.process = {
          executable: appPath,
          name: basename(appPath)
        };
        var wfpPid = hexToDecimal(eventData.ProcessID);
        if (wfpPid !== undefined) __e.process.pid = wfpPid;
      }

      __e.event.category = ['network'];
      __e.event.type = allowed ? ['connection', 'allowed'] : ['connection', 'denied'];
      __e.event.outcome = allowed ? 'success' : 'failure';
      break;
    }
    case '4689': { // process exit
      var exitProc = {};
      if (eventData.ProcessName) {
        exitProc.executable = eventData.ProcessName;
        exitProc.name = basename(eventData.ProcessName);
      }
      var exitPid = hexToDecimal(eventData.ProcessId);
      if (exitPid !== undefined) exitProc.pid = exitPid;
      __e.process = exitProc;

      __e.user = {
        name: eventData.SubjectUserName,
        domain: eventData.SubjectDomainName,
        id: eventData.SubjectUserSid
      };

      if (eventData.Status) {
        __e.event.outcome = (eventData.Status === '0x0') ? 'success' : 'failure';
      }
      __e.event.category = ['process'];
      __e.event.type = ['end'];
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
      __e.event.category = ['authentication'];
      __e.event.type = ['start'];
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
  extractEventData: extractEventData,
  sysmonVal: sysmonVal,
  splitDomainUser: splitDomainUser,
  parseHashes: parseHashes,
  sysmonProcess: sysmonProcess,
  validAddr: validAddr,
  networkDirection: networkDirection,
  ianaProtoName: ianaProtoName,
  normalizeDevicePath: normalizeDevicePath,
  eventDataset: eventDataset
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

  // Verbatim from eforge/output/data/WS-ANALYST-01.corp.example.com/windows_event_security.xml
  // -- a routine 5156 with Application="System" (PID 4, the kernel), an
  // internal destination. No 5157 sample exists anywhere in real
  // EvidenceForge output for this scenario (grep confirms zero), so per the
  // "never invent a fixture" rule there is no dedicated 5157 XML test --
  // 5157 shares the 5156 code path end-to-end except for the
  // allowed/denied branch, which is covered by unit-testing networkDirection
  // and the allowed/outcome ternary logic directly below.
  var SAMPLE_5156_INTERNAL =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    \n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    \n' +
    '    <EventID>5156</EventID>\n' +
    '    <Version>1</Version>\n' +
    '    <Level>0</Level>\n' +
    '    <Task>12810</Task>\n' +
    '    <Opcode>0</Opcode>\n' +
    '    <Keywords>0x8020000000000000</Keywords>\n' +
    '    <TimeCreated SystemTime="2026-07-13T04:53:23.5940705Z"/>\n' +
    '    <EventRecordID>348484</EventRecordID>\n' +
    '    <Correlation/>\n' +
    '    <Execution ProcessID="4" ThreadID="164"/>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-ANALYST-01.corp.example.com</Computer>\n' +
    '    \n' +
    '    <Security/>\n' +
    '    \n' +
    '  </System>\n' +
    '  \n' +
    '  <EventData>\n' +
    '    \n' +
    '    <Data Name="ProcessID">4</Data>\n' +
    '    <Data Name="Application">System</Data>\n' +
    '    <Data Name="Direction">%%14593</Data>\n' +
    '    <Data Name="SourceAddress">10.0.10.50</Data>\n' +
    '    <Data Name="SourcePort">64063</Data>\n' +
    '    <Data Name="DestAddress">10.0.1.10</Data>\n' +
    '    <Data Name="DestPort">445</Data>\n' +
    '    <Data Name="Protocol">6</Data>\n' +
    '    <Data Name="FilterRTID">23582</Data>\n' +
    '    <Data Name="LayerName">%%14611</Data>\n' +
    '    <Data Name="LayerRTID">48</Data>\n' +
    '    <Data Name="RemoteUserID">S-1-0-0</Data>\n' +
    '    <Data Name="RemoteMachineID">S-1-0-0</Data>\n' +
    '    \n' +
    '  </EventData>\n' +
    '  \n' +
    '</Event>\n';

  // Verbatim -- evt-003, the actual C2 connection (198.51.100.10:443) from
  // GROUND_TRUTH.md. Application is a device path (svchost.exe, PID 3744) --
  // EvidenceForge does not correlate this event to the earlier powershell.exe
  // process, so process.name here is genuinely svchost.exe, not powershell.exe.
  var SAMPLE_5156_C2 =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    \n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    \n' +
    '    <EventID>5156</EventID>\n' +
    '    <Version>1</Version>\n' +
    '    <Level>0</Level>\n' +
    '    <Task>12810</Task>\n' +
    '    <Opcode>0</Opcode>\n' +
    '    <Keywords>0x8020000000000000</Keywords>\n' +
    '    <TimeCreated SystemTime="2026-07-13T05:15:45.0775307Z"/>\n' +
    '    <EventRecordID>350093</EventRecordID>\n' +
    '    <Correlation/>\n' +
    '    <Execution ProcessID="4" ThreadID="132"/>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-ANALYST-01.corp.example.com</Computer>\n' +
    '    \n' +
    '    <Security/>\n' +
    '    \n' +
    '  </System>\n' +
    '  \n' +
    '  <EventData>\n' +
    '    \n' +
    '    <Data Name="ProcessID">3744</Data>\n' +
    '    <Data Name="Application">\\device\\harddiskvolume1\\windows\\system32\\svchost.exe</Data>\n' +
    '    <Data Name="Direction">%%14593</Data>\n' +
    '    <Data Name="SourceAddress">10.0.10.50</Data>\n' +
    '    <Data Name="SourcePort">59813</Data>\n' +
    '    <Data Name="DestAddress">198.51.100.10</Data>\n' +
    '    <Data Name="DestPort">443</Data>\n' +
    '    <Data Name="Protocol">6</Data>\n' +
    '    <Data Name="FilterRTID">23599</Data>\n' +
    '    <Data Name="LayerName">%%14611</Data>\n' +
    '    <Data Name="LayerRTID">48</Data>\n' +
    '    <Data Name="RemoteUserID">S-1-0-0</Data>\n' +
    '    <Data Name="RemoteMachineID">S-1-0-0</Data>\n' +
    '    \n' +
    '  </EventData>\n' +
    '  \n' +
    '</Event>\n';

  // Verbatim from the same file -- a routine 4689 process exit (SYSTEM
  // reaping wsqmcons.exe), one of the 126 in this dataset the pipeline
  // previously mapped zero ECS for.
  var SAMPLE_4689 =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    \n' +
    '    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>\n' +
    '    \n' +
    '    <EventID>4689</EventID>\n' +
    '    <Version>0</Version>\n' +
    '    <Level>0</Level>\n' +
    '    <Task>13313</Task>\n' +
    '    <Opcode>0</Opcode>\n' +
    '    <Keywords>0x8020000000000000</Keywords>\n' +
    '    <TimeCreated SystemTime="2026-07-13T05:01:31.3076357Z"/>\n' +
    '    <EventRecordID>349730</EventRecordID>\n' +
    '    <Correlation/>\n' +
    '    <Execution ProcessID="4" ThreadID="340"/>\n' +
    '    <Channel>Security</Channel>\n' +
    '    <Computer>WS-ANALYST-01.corp.example.com</Computer>\n' +
    '    \n' +
    '    <Security/>\n' +
    '    \n' +
    '  </System>\n' +
    '  \n' +
    '  <EventData>\n' +
    '    \n' +
    '    <Data Name="SubjectUserSid">S-1-5-18</Data>\n' +
    '    <Data Name="SubjectUserName">SYSTEM</Data>\n' +
    '    <Data Name="SubjectDomainName">NT AUTHORITY</Data>\n' +
    '    <Data Name="SubjectLogonId">0x3e7</Data>\n' +
    '    <Data Name="Status">0x0</Data>\n' +
    '    <Data Name="ProcessId">0x1494</Data>\n' +
    '    <Data Name="ProcessName">C:\\Windows\\System32\\wsqmcons.exe</Data>\n' +
    '    \n' +
    '  </EventData>\n' +
    '  \n' +
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

  test('host.name is set as an ECS object, not a scalar string', function () {
    var e = { _raw: SAMPLE_4624 };
    applyToEvent(e);
    assert.strictEqual(typeof e.host, 'object');
    assert.strictEqual(e.host.name, 'WS-ANALYST-01.corp.example.com');
    assert.strictEqual(e.host.hostname, 'WS-ANALYST-01', 'host.hostname is the short (first-label) name');
  });

  test('event.kind/module/dataset are set on every event type (Security channel)', function () {
    var e = { _raw: SAMPLE_4624 };
    applyToEvent(e);
    assert.strictEqual(e.event.kind, 'event');
    assert.strictEqual(e.event.module, 'windows');
    assert.strictEqual(e.event.dataset, 'windows.security');
  });

  test('5156 (internal dest, Application="System"): network mapping, process, direction, protocol', function () {
    var e = { _raw: SAMPLE_5156_INTERNAL };
    applyToEvent(e);
    assert.strictEqual(e.event.code, '5156');
    assert.deepStrictEqual(e.event.category, ['network']);
    assert.deepStrictEqual(e.event.type, ['connection', 'allowed']);
    assert.strictEqual(e.event.outcome, 'success');
    assert.strictEqual(e.source.ip, '10.0.10.50');
    assert.strictEqual(e.source.port, 64063);
    assert.strictEqual(e.destination.ip, '10.0.1.10');
    assert.strictEqual(e.destination.port, 445);
    assert.strictEqual(e.network.transport, 'tcp', 'Protocol "6" is an IANA number, must resolve to tcp not "6"');
    assert.strictEqual(e.network.direction, 'outbound', '%%14593 is the outbound resource code');
    assert.strictEqual(e.process.executable, 'System', 'a bare device-less Application value passes through unchanged');
    assert.strictEqual(e.process.name, 'System');
    assert.strictEqual(e.process.pid, 4, 'ProcessID (capital D) decodes via hexToDecimal same as decimal 4');
  });

  test('5156 external C2 connection (evt-003, 198.51.100.10:443): destination.ip is queryable, device path normalized', function () {
    var e = { _raw: SAMPLE_5156_C2 };
    applyToEvent(e);
    assert.strictEqual(e.destination.ip, '198.51.100.10');
    assert.strictEqual(e.destination.port, 443);
    assert.strictEqual(e.network.transport, 'tcp');
    assert.strictEqual(e.process.executable, 'C:\\windows\\system32\\svchost.exe', 'harddiskvolume1 normalizes to C: per the documented volume-1 assumption');
    assert.strictEqual(e.process.name, 'svchost.exe');
    assert.strictEqual(e.process.pid, 3744);
  });

  test('5156/5157 address guard: "-" and "::" must not set destination.ip/source.ip (mirrors the 4624/4625 IpAddress guard)', function () {
    assert.strictEqual(validAddr('-'), false);
    assert.strictEqual(validAddr('::'), false);
    assert.strictEqual(validAddr(''), false);
    assert.strictEqual(validAddr(undefined), false);
    assert.strictEqual(validAddr('198.51.100.10'), true);

    var e = { _raw: SAMPLE_5156_C2.replace('<Data Name="SourceAddress">10.0.10.50</Data>', '<Data Name="SourceAddress">-</Data>') };
    applyToEvent(e);
    assert.strictEqual(e.source, undefined, '"-" source address must not become a bogus source.ip');
    assert.strictEqual(e.destination.ip, '198.51.100.10', 'destination is unaffected by the source guard');
  });

  test('5157 shares the 5156 code path but flips to denied/failure (no real 5157 sample exists in EvidenceForge output for this scenario -- verified by grep -- so this exercises the code path via the real 5156 fixture with EventID substituted, not a fabricated event)', function () {
    var e = { _raw: SAMPLE_5156_INTERNAL.replace('<EventID>5156</EventID>', '<EventID>5157</EventID>') };
    applyToEvent(e);
    assert.strictEqual(e.event.code, '5157');
    assert.deepStrictEqual(e.event.type, ['connection', 'denied']);
    assert.strictEqual(e.event.outcome, 'failure');
    assert.strictEqual(e.destination.ip, '10.0.1.10', 'address mapping is identical to 5156');
  });

  test('ianaProtoName: numeric IANA protocol numbers resolve to names, not lowercased Sysmon-style strings', function () {
    assert.strictEqual(ianaProtoName('6'), 'tcp');
    assert.strictEqual(ianaProtoName('17'), 'udp');
    assert.strictEqual(ianaProtoName('1'), 'icmp');
    assert.strictEqual(ianaProtoName('58'), 'ipv6-icmp');
    assert.strictEqual(ianaProtoName('999'), '999', 'unknown protocol numbers pass through rather than being dropped');
  });

  test('networkDirection: accepts the %% resource codes and literal words', function () {
    assert.strictEqual(networkDirection('%%14592'), 'inbound');
    assert.strictEqual(networkDirection('%%14593'), 'outbound');
    assert.strictEqual(networkDirection('inbound'), 'inbound');
    assert.strictEqual(networkDirection('Outbound'), 'outbound');
    assert.strictEqual(networkDirection('%%99999'), undefined);
  });

  test('normalizeDevicePath: volume 1 maps to C:, other volumes pass through unchanged', function () {
    assert.strictEqual(normalizeDevicePath('\\device\\harddiskvolume1\\windows\\system32\\svchost.exe'), 'C:\\windows\\system32\\svchost.exe');
    assert.strictEqual(normalizeDevicePath('\\device\\harddiskvolume2\\data\\file.exe'), '\\device\\harddiskvolume2\\data\\file.exe', 'no assumption is made for non-1 volumes');
    assert.strictEqual(normalizeDevicePath('System'), 'System', 'non-device-path values pass through unchanged');
  });

  test('4689 process exit: process/user/outcome mapped, event.category=[process] event.type=[end]', function () {
    var e = { _raw: SAMPLE_4689 };
    applyToEvent(e);
    assert.strictEqual(e.event.code, '4689');
    assert.deepStrictEqual(e.event.category, ['process']);
    assert.deepStrictEqual(e.event.type, ['end']);
    assert.strictEqual(e.event.outcome, 'success', 'Status 0x0 maps to success');
    assert.strictEqual(e.process.pid, 0x1494);
    assert.strictEqual(e.process.pid, 5268);
    assert.strictEqual(e.process.executable, 'C:\\Windows\\System32\\wsqmcons.exe');
    assert.strictEqual(e.process.name, 'wsqmcons.exe');
    assert.strictEqual(e.user.name, 'SYSTEM');
    assert.strictEqual(e.user.domain, 'NT AUTHORITY');
    assert.strictEqual(e.user.id, 'S-1-5-18');
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

  // --- Sysmon (verbatim from eforge/output/data/*/windows_event_sysmon.xml) ---

  function sysmonEvent(eventId, task, body) {
    return '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
      '  <System>\n' +
      '    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>\n' +
      '    <EventID>' + eventId + '</EventID>\n' +
      '    <Task>' + task + '</Task>\n' +
      '    <TimeCreated SystemTime="2026-07-13T05:40:59.6382827Z"/>\n' +
      '    <EventRecordID>451415</EventRecordID>\n' +
      '    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>\n' +
      '    <Computer>WS-EXEC-01.corp.example.com</Computer>\n' +
      '  </System>\n' +
      '  <EventData>\n' + body + '  </EventData>\n' +
      '</Event>\n';
  }

  var SAMPLE_SYSMON_1_MIMIKATZ = sysmonEvent(1, 1,
    '    <Data Name="ProcessGuid">{f6ab85b5-7a6b-6a54-9d02-001080f67d88}</Data>\n' +
    '    <Data Name="ProcessId">7372</Data>\n' +
    '    <Data Name="Image">C:\\Windows\\Temp\\mimikatz.exe</Data>\n' +
    '    <Data Name="OriginalFileName">-</Data>\n' +
    '    <Data Name="CommandLine">mimikatz.exe privilege::debug sekurlsa::logonpasswords exit</Data>\n' +
    '    <Data Name="CurrentDirectory">C:\\Windows\\Temp\\</Data>\n' +
    '    <Data Name="User">CORP\\attacker</Data>\n' +
    '    <Data Name="Hashes">SHA1=80520C50C30D947A68E2E01E4B92DF5FF29928FA,MD5=D6395FA4C4ABC4A284744C04BC2C6207,SHA256=69D6A3AB75BCB21819F7D54E69E6BA2CB32C8E958F27473FD54099ADEB4BB353,IMPHASH=D775FDE08B202AEDA21B2DF864344D45</Data>\n' +
    '    <Data Name="ParentProcessId">4820</Data>\n' +
    '    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>\n' +
    '    <Data Name="ParentCommandLine">cmd.exe /c mimikatz.exe</Data>\n');

  // The exact 388-char payload from GROUND_TRUTH -- the doc P3 says must never
  // be silently dropped.
  var ENC_PAYLOAD = 'powershell.exe -enc JABkAGMAID0AIAAoAFsAUwB5AHMAdABlAG0ALgBEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGkAYwBlAHMALgBBAGMAdABpAHYAZQBEAGkAcgBlAGMAdABvAHIAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0AEQAbwBtAGEAaQBuACkAKQA7ACAAJABkAGMALgBHAGUAdABEAGkAcgBlAGMAdABvAHIAeQBFAG4AdAByAHkAKAApAC4AQwBoAGkAbABkAHIAZQBuACAAfAAgAD8AewAkAF8ALgBTAGMAaABlAG0AYQBDAGwAYQBzAHMATgBhAG0AZQAgAC0AZQBxACAAJwB1AHMAZQByACcAfQA=';

  var SAMPLE_SYSMON_1_ENCODED_PS = sysmonEvent(1, 1,
    '    <Data Name="ProcessId">5768</Data>\n' +
    '    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>\n' +
    '    <Data Name="OriginalFileName">PowerShell.EXE</Data>\n' +
    '    <Data Name="CommandLine">' + ENC_PAYLOAD + '</Data>\n' +
    '    <Data Name="User">CORP\\attacker</Data>\n');

  var SAMPLE_SYSMON_3 = sysmonEvent(3, 3,
    '    <Data Name="ProcessId">3696</Data>\n' +
    '    <Data Name="Image">C:\\Windows\\System32\\lsass.exe</Data>\n' +
    '    <Data Name="User">NT AUTHORITY\\SYSTEM</Data>\n' +
    '    <Data Name="Protocol">udp</Data>\n' +
    '    <Data Name="SourceIp">10.0.10.50</Data>\n' +
    '    <Data Name="SourcePort">49865</Data>\n' +
    '    <Data Name="SourcePortName">-</Data>\n' +
    '    <Data Name="DestinationIp">10.0.1.10</Data>\n' +
    '    <Data Name="DestinationHostname">SRV-DC-01.corp.example.com</Data>\n' +
    '    <Data Name="DestinationPort">88</Data>\n');

  var SAMPLE_SYSMON_11 = sysmonEvent(11, 11,
    '    <Data Name="ProcessId">5488</Data>\n' +
    '    <Data Name="Image">C:\\Windows\\Temp\\KB5034441_update.exe</Data>\n' +
    '    <Data Name="User">CORP\\jsmith</Data>\n' +
    '    <Data Name="TargetFilename">C:\\Windows\\Temp\\MSI45070.tmp</Data>\n');

  // Same EID as Sysmon process-create, different provider -- must NOT be mapped.
  var SAMPLE_SYSTEM_EID1 =
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n' +
    '  <System>\n' +
    '    <Provider Name="Microsoft-Windows-Kernel-General"/>\n' +
    '    <EventID>1</EventID>\n' +
    '    <TimeCreated SystemTime="2026-07-13T05:40:59.0000000Z"/>\n' +
    '    <Channel>System</Channel>\n' +
    '    <Computer>WS-EXEC-01.corp.example.com</Computer>\n' +
    '  </System>\n' +
    '  <EventData><Data Name="Image">not-a-process-create</Data></EventData>\n' +
    '</Event>\n';

  test('Sysmon 1: Image/CommandLine/CurrentDirectory map to ECS process.*', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.strictEqual(e.process.executable, 'C:\\Windows\\Temp\\mimikatz.exe');
    assert.strictEqual(e.process.name, 'mimikatz.exe');
    assert.strictEqual(e.process.command_line, 'mimikatz.exe privilege::debug sekurlsa::logonpasswords exit');
    assert.strictEqual(e.process.working_directory, 'C:\\Windows\\Temp\\');
    assert.strictEqual(e.process.pid, 7372, 'Sysmon ProcessId is decimal, not hex');
    assert.strictEqual(e.process.entity_id, '{f6ab85b5-7a6b-6a54-9d02-001080f67d88}');
    assert.deepStrictEqual(e.process.args, ['mimikatz.exe', 'privilege::debug', 'sekurlsa::logonpasswords', 'exit']);
  });

  test('Sysmon 1: ParentImage/ParentCommandLine map to ECS process.parent.*', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.strictEqual(e.process.parent.executable, 'C:\\Windows\\System32\\cmd.exe');
    assert.strictEqual(e.process.parent.name, 'cmd.exe');
    assert.strictEqual(e.process.parent.command_line, 'cmd.exe /c mimikatz.exe');
    assert.strictEqual(e.process.parent.pid, 4820);
  });

  test('Sysmon 1: "DOMAIN\\user" splits into ECS user.domain + user.name', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.strictEqual(e.user.domain, 'CORP');
    assert.strictEqual(e.user.name, 'attacker');
  });

  test('Sysmon 1: Hashes CSV splits into process.hash.* and pe.imphash', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.strictEqual(e.process.hash.md5, 'D6395FA4C4ABC4A284744C04BC2C6207');
    assert.strictEqual(e.process.hash.sha256, '69D6A3AB75BCB21819F7D54E69E6BA2CB32C8E958F27473FD54099ADEB4BB353');
    assert.strictEqual(e.process.pe.imphash, 'D775FDE08B202AEDA21B2DF864344D45');
    assert.strictEqual(e.process.hash.imphash, undefined, 'imphash belongs under pe, not hash');
  });

  test('Sysmon 1: OriginalFileName "-" is dropped, not indexed as a literal "-"', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.strictEqual(e.process.pe.original_file_name, undefined);
    // ...but a real OriginalFileName IS mapped (the rename-evasion signal).
    var e2 = { _raw: SAMPLE_SYSMON_1_ENCODED_PS };
    applyToEvent(e2);
    assert.strictEqual(e2.process.pe.original_file_name, 'PowerShell.EXE');
  });

  test('Sysmon 1: the 388-char -enc payload survives mapping intact (P3)', function () {
    var e = { _raw: SAMPLE_SYSMON_1_ENCODED_PS };
    applyToEvent(e);
    assert.strictEqual(e.process.command_line, ENC_PAYLOAD);
    assert.ok(e.process.command_line.length > 256, 'payload must exceed the 256-char ignore_above that was silently dropping it');
  });

  test('Sysmon 1: event.category/event.type use ECS allowed_values', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.deepStrictEqual(e.event.category, ['process']);
    assert.deepStrictEqual(e.event.type, ['start']);
    assert.strictEqual(e.event.code, '1');
  });

  test('event.dataset maps the Sysmon channel to windows.sysmon_operational', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.strictEqual(e.event.dataset, 'windows.sysmon_operational');
  });

  test('Sysmon 3: network connection maps source/destination/network.transport', function () {
    var e = { _raw: SAMPLE_SYSMON_3 };
    applyToEvent(e);
    assert.strictEqual(e.source.ip, '10.0.10.50');
    assert.strictEqual(e.source.port, 49865);
    assert.strictEqual(e.destination.ip, '10.0.1.10');
    assert.strictEqual(e.destination.port, 88);
    assert.strictEqual(e.destination.domain, 'SRV-DC-01.corp.example.com');
    assert.strictEqual(e.network.transport, 'udp');
    assert.strictEqual(e.process.name, 'lsass.exe');
    assert.deepStrictEqual(e.event.category, ['network']);
  });

  test('Sysmon 11: TargetFilename maps to file.path/name/directory', function () {
    var e = { _raw: SAMPLE_SYSMON_11 };
    applyToEvent(e);
    assert.strictEqual(e.file.path, 'C:\\Windows\\Temp\\MSI45070.tmp');
    assert.strictEqual(e.file.name, 'MSI45070.tmp');
    assert.strictEqual(e.file.directory, 'C:\\Windows\\Temp');
    assert.strictEqual(e.process.name, 'KB5034441_update.exe');
    assert.deepStrictEqual(e.event.category, ['file']);
    assert.deepStrictEqual(e.event.type, ['creation']);
  });

  test('EID 1 from a NON-Sysmon provider is not mapped as a process creation', function () {
    var e = { _raw: SAMPLE_SYSTEM_EID1 };
    applyToEvent(e);
    assert.strictEqual(e.process, undefined, 'System-channel EID 1 must not become process.*');
    assert.strictEqual(e.event.category, undefined);
    assert.strictEqual(e.event.code, '1', 'but it is still a real event with a code');
  });

  test('Sysmon: winlog.event_data.* is still preserved alongside ECS', function () {
    var e = { _raw: SAMPLE_SYSMON_1_MIMIKATZ };
    applyToEvent(e);
    assert.strictEqual(e.winlog.event_data.Image, 'C:\\Windows\\Temp\\mimikatz.exe');
    assert.strictEqual(e.winlog.event_data.User, 'CORP\\attacker');
    assert.strictEqual(e.winlog.event_id, 1);
  });

  console.log('');
  if (failures > 0) {
    console.log(failures + ' test(s) failed.');
    process.exit(1);
  } else {
    console.log('All tests passed.');
  }
}
