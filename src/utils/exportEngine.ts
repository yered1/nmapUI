import type { NmapScan, NmapHost, Note, ExportOptions, ExportFormat } from '../types/nmap';

export function exportData(scan: NmapScan, hosts: NmapHost[], options: ExportOptions): string {
  switch (options.format) {
    case 'csv': return exportCSV(scan, hosts, options);
    case 'json': return exportJSON(scan, hosts, options);
    case 'html': return exportHTML(scan, hosts, options);
    case 'xml': return exportXML(scan, hosts, options);
    case 'markdown': return exportMarkdown(scan, hosts, options);
    default: return '';
  }
}

export function getExportFilename(format: ExportFormat): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const ext = format === 'markdown' ? 'md' : format;
  return `nmap-results-${ts}.${ext}`;
}

export function getExportMimeType(format: ExportFormat): string {
  switch (format) {
    case 'csv': return 'text/csv';
    case 'json': return 'application/json';
    case 'html': return 'text/html';
    case 'xml': return 'application/xml';
    case 'markdown': return 'text/markdown';
    default: return 'text/plain';
  }
}

function exportCSV(scan: NmapScan, hosts: NmapHost[], options: ExportOptions): string {
  const rows: string[][] = [];
  const headers = ['IP', 'IPv6', 'MAC', 'MAC Vendor', 'Hostname', 'Status', 'Status Reason'];

  if (options.includeOS) {
    headers.push('OS', 'OS Accuracy', 'OS Family', 'OS Vendor');
  }
  if (options.includePorts) {
    headers.push('Port', 'Protocol', 'State', 'Service', 'Product', 'Version', 'Extra Info');
  }
  if (options.includeScripts) {
    headers.push('Script ID', 'Script Output');
  }
  if (options.includeTrace) {
    headers.push('Distance', 'Uptime', 'Last Boot');
  }

  rows.push(headers);

  for (const host of hosts) {
    if (options.includePorts && host.ports.length > 0) {
      for (const port of host.ports) {
        const row = [
          host.ip, host.ipv6, host.mac,
          host.addresses.find(a => a.addrtype === 'mac')?.vendor || '',
          host.hostname, host.status.state, host.status.reason,
        ];
        if (options.includeOS) {
          row.push(
            host.mainOS,
            String(host.os.osmatch[0]?.accuracy || ''),
            host.os.osmatch[0]?.osclass[0]?.osfamily || '',
            host.os.osmatch[0]?.osclass[0]?.vendor || '',
          );
        }
        row.push(
          String(port.portid), port.protocol, port.state.state,
          port.service?.name || '', port.service?.product || '',
          port.service?.version || '', port.service?.extrainfo || '',
        );
        if (options.includeScripts) {
          const scripts = port.scripts.map(s => s.id).join('; ');
          const outputs = port.scripts.map(s => s.output.replace(/\n/g, ' ')).join('; ');
          row.push(scripts, outputs);
        }
        if (options.includeTrace) {
          row.push(
            String(host.distance || ''),
            String(host.uptime?.seconds || ''),
            host.uptime?.lastboot || '',
          );
        }
        rows.push(row);
      }
    } else {
      const row = [
        host.ip, host.ipv6, host.mac,
        host.addresses.find(a => a.addrtype === 'mac')?.vendor || '',
        host.hostname, host.status.state, host.status.reason,
      ];
      if (options.includeOS) {
        row.push(
          host.mainOS,
          String(host.os.osmatch[0]?.accuracy || ''),
          host.os.osmatch[0]?.osclass[0]?.osfamily || '',
          host.os.osmatch[0]?.osclass[0]?.vendor || '',
        );
      }
      if (options.includePorts) {
        row.push('', '', '', '', '', '', '');
      }
      if (options.includeScripts) {
        row.push('', '');
      }
      if (options.includeTrace) {
        row.push(
          String(host.distance || ''),
          String(host.uptime?.seconds || ''),
          host.uptime?.lastboot || '',
        );
      }
      rows.push(row);
    }
  }

  return rows.map(row =>
    row.map(cell => {
      const str = String(cell);
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    }).join(',')
  ).join('\n');
}

function exportJSON(scan: NmapScan, hosts: NmapHost[], options: ExportOptions): string {
  const output: any = {
    scanInfo: {
      scanner: scan.scanner,
      args: scan.args,
      startTime: scan.startstr,
      version: scan.version,
      scanTypes: scan.scaninfo.map(si => ({ type: si.type, protocol: si.protocol })),
      duration: scan.scanDuration,
    },
    summary: {
      totalHosts: scan.totalHosts,
      hostsUp: scan.hostsUp,
      hostsDown: scan.hostsDown,
    },
    hosts: hosts.map(host => {
      const h: any = {
        ip: host.ip,
        ipv6: host.ipv6,
        mac: host.mac,
        macVendor: host.addresses.find(a => a.addrtype === 'mac')?.vendor || '',
        hostnames: host.hostnames.map(hn => hn.name),
        status: host.status.state,
        statusReason: host.status.reason,
      };

      if (options.includeOS) {
        h.os = {
          bestMatch: host.mainOS,
          matches: host.os.osmatch.map(om => ({
            name: om.name,
            accuracy: om.accuracy,
            classes: om.osclass.map(oc => ({
              vendor: oc.vendor,
              family: oc.osfamily,
              generation: oc.osgen,
              type: oc.type,
              cpes: oc.cpes,
            })),
          })),
        };
      }

      if (options.includePorts) {
        h.ports = host.ports.map(p => {
          const port: any = {
            number: p.portid,
            protocol: p.protocol,
            state: p.state.state,
            reason: p.state.reason,
          };
          if (p.service) {
            port.service = {
              name: p.service.name,
              product: p.service.product,
              version: p.service.version,
              extrainfo: p.service.extrainfo,
              tunnel: p.service.tunnel,
              cpes: p.service.cpes,
            };
          }
          if (options.includeScripts && p.scripts.length > 0) {
            port.scripts = p.scripts.map(s => ({ id: s.id, output: s.output }));
          }
          return port;
        });
      }

      if (options.includeScripts && host.hostscripts.length > 0) {
        h.hostScripts = host.hostscripts.map(s => ({ id: s.id, output: s.output }));
      }

      if (options.includeTrace) {
        h.distance = host.distance;
        h.uptime = host.uptime;
        if (host.trace) {
          h.trace = {
            port: host.trace.port,
            protocol: host.trace.proto,
            hops: host.trace.hops,
          };
        }
      }

      return h;
    }),
  };

  if (options.includeNotes && options.notes && options.notes.length > 0) {
    output.notes = options.notes.map((n: Note) => ({
      id: n.id,
      title: n.title,
      content: n.content,
      targets: n.targets.map(t => ({
        ip: t.ip,
        port: t.portId,
        protocol: t.protocol,
      })),
      screenshots: n.screenshots.map(s => ({
        fileName: s.fileName,
        dataUrl: s.dataUrl,
      })),
      createdAt: new Date(n.createdAt).toISOString(),
      updatedAt: new Date(n.updatedAt).toISOString(),
    }));
  }

  return JSON.stringify(output, null, 2);
}

function exportHTML(scan: NmapScan, hosts: NmapHost[], options: ExportOptions): string {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nmap Scan Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; line-height: 1.6; }
  h1 { color: #38bdf8; margin-bottom: 0.5rem; font-size: 1.8rem; }
  h2 { color: #7dd3fc; margin: 1.5rem 0 0.75rem; font-size: 1.3rem; border-bottom: 1px solid #334155; padding-bottom: 0.3rem; }
  h3 { color: #93c5fd; margin: 1rem 0 0.5rem; font-size: 1.1rem; }
  .meta { color: #94a3b8; margin-bottom: 1.5rem; font-size: 0.9rem; }
  .meta code { background: #1e293b; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }
  .summary-card { background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; border: 1px solid #334155; }
  .summary-card .number { font-size: 2rem; font-weight: bold; color: #38bdf8; }
  .summary-card .label { font-size: 0.85rem; color: #94a3b8; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; background: #1e293b; border-radius: 8px; overflow: hidden; }
  th { background: #0f172a; color: #7dd3fc; text-align: left; padding: 0.6rem 0.8rem; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
  td { padding: 0.5rem 0.8rem; border-top: 1px solid #334155; font-size: 0.9rem; }
  tr:hover td { background: #334155; }
  .state-open { color: #4ade80; font-weight: 600; }
  .state-closed { color: #f87171; }
  .state-filtered { color: #fbbf24; }
  .host-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.2rem; margin: 1rem 0; }
  .host-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }
  .host-ip { font-size: 1.2rem; font-weight: bold; color: #38bdf8; }
  .host-hostname { color: #94a3b8; }
  .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .tag-up { background: rgba(74,222,128,0.15); color: #4ade80; }
  .tag-down { background: rgba(248,113,113,0.15); color: #f87171; }
  .script-output { background: #0f172a; padding: 0.75rem; border-radius: 4px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; margin: 0.5rem 0; overflow-x: auto; }
  @media print { body { background: #fff; color: #1e293b; } .host-card { border-color: #e2e8f0; } table, th, td { border: 1px solid #e2e8f0; } }
</style>
</head>
<body>
<h1>Nmap Scan Report</h1>
<div class="meta">
  <div>Command: <code>${esc(scan.args)}</code></div>
  <div>Started: ${esc(scan.startstr)} | Duration: ${scan.scanDuration}s | Nmap ${esc(scan.version)}</div>
</div>

<div class="summary-grid">
  <div class="summary-card"><div class="number">${scan.totalHosts}</div><div class="label">Total Hosts</div></div>
  <div class="summary-card"><div class="number">${scan.hostsUp}</div><div class="label">Hosts Up</div></div>
  <div class="summary-card"><div class="number">${scan.hostsDown}</div><div class="label">Hosts Down</div></div>
  <div class="summary-card"><div class="number">${scan.uniquePorts.filter(p => p.state === 'open').length}</div><div class="label">Open Ports</div></div>
  <div class="summary-card"><div class="number">${scan.uniqueServices.length}</div><div class="label">Services</div></div>
</div>
`;

  for (const host of hosts) {
    html += `
<div class="host-card">
  <div class="host-header">
    <span class="host-ip">${esc(host.ip || host.ipv6)}</span>
    ${host.hostname ? `<span class="host-hostname">(${esc(host.hostname)})</span>` : ''}
    <span class="tag tag-${host.status.state}">${host.status.state.toUpperCase()}</span>
  </div>`;

    if (host.mac) {
      const vendor = host.addresses.find(a => a.addrtype === 'mac')?.vendor || '';
      html += `<div style="font-size:0.85rem;color:#94a3b8;">MAC: ${esc(host.mac)}${vendor ? ` (${esc(vendor)})` : ''}</div>`;
    }

    if (options.includeOS && host.mainOS) {
      html += `<div style="margin-top:0.5rem;"><strong>OS:</strong> ${esc(host.mainOS)} (${host.os.osmatch[0]?.accuracy || 0}% accuracy)</div>`;
    }

    if (options.includePorts && host.ports.length > 0) {
      html += `
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
    <tbody>`;
      for (const port of host.ports) {
        const stateClass = port.state.state === 'open' ? 'state-open' :
          port.state.state === 'closed' ? 'state-closed' : 'state-filtered';
        html += `
      <tr>
        <td>${port.portid}/${esc(port.protocol)}</td>
        <td class="${stateClass}">${esc(port.state.state)}</td>
        <td>${esc(port.service?.name || '')}</td>
        <td>${esc(port.service?.product || '')}</td>
        <td>${esc(port.service?.version || '')}${port.service?.extrainfo ? ' (' + esc(port.service.extrainfo) + ')' : ''}</td>
      </tr>`;

        if (options.includeScripts && port.scripts.length > 0) {
          for (const script of port.scripts) {
            html += `
      <tr><td colspan="5"><strong>${esc(script.id)}:</strong><div class="script-output">${esc(script.output)}</div></td></tr>`;
          }
        }
      }
      html += `</tbody></table>`;
    }

    if (options.includeScripts && host.hostscripts.length > 0) {
      html += `<h3>Host Scripts</h3>`;
      for (const script of host.hostscripts) {
        html += `<div><strong>${esc(script.id)}:</strong><div class="script-output">${esc(script.output)}</div></div>`;
      }
    }

    if (options.includeTrace && host.trace) {
      html += `<h3>Traceroute</h3><table><thead><tr><th>TTL</th><th>RTT</th><th>IP</th><th>Host</th></tr></thead><tbody>`;
      for (const hop of host.trace.hops) {
        html += `<tr><td>${hop.ttl}</td><td>${hop.rtt}ms</td><td>${esc(hop.ipaddr)}</td><td>${esc(hop.host || '')}</td></tr>`;
      }
      html += `</tbody></table>`;
    }

    html += `</div>`;
  }

  if (options.includeNotes && options.notes && options.notes.length > 0) {
    html += `<h2>Notes</h2>`;
    for (const note of options.notes) {
      html += `<div class="host-card">`;
      html += `<div class="host-header"><span class="host-ip">${esc(note.title)}</span></div>`;
      if (note.targets.length > 0) {
        html += `<div style="margin:4px 0;font-size:0.85rem;color:#94a3b8;">Targets: ${note.targets.map(t => esc(t.ip) + (t.portId ? `:${t.portId}/${t.protocol || 'tcp'}` : '')).join(', ')}</div>`;
      }
      html += `<div style="white-space:pre-wrap;margin-top:8px;">${esc(note.content)}</div>`;
      if (note.screenshots.length > 0) {
        html += `<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">`;
        for (const ss of note.screenshots) {
          // Only allow data: image URIs to prevent external resource loading
          const safeSrc = ss.dataUrl.startsWith('data:image/') ? esc(ss.dataUrl) : '';
          html += `<img src="${safeSrc}" alt="${esc(ss.fileName)}" style="max-width:300px;max-height:200px;border-radius:4px;border:1px solid #334155;" />`;
        }
        html += `</div>`;
      }
      html += `<div style="font-size:0.75rem;color:#64748b;margin-top:8px;">Created: ${new Date(note.createdAt).toLocaleString()} | Updated: ${new Date(note.updatedAt).toLocaleString()}</div>`;
      html += `</div>`;
    }
  }

  html += `
<div class="meta" style="margin-top: 2rem; text-align: center;">
  Generated by NmapUI | ${new Date().toISOString()}
</div>
</body></html>`;

  return html;
}

function exportXML(scan: NmapScan, hosts: NmapHost[], _options: ExportOptions): string {
  // Re-export as simplified XML
  let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
  xml += `<nmapui-export scanner="${esc(scan.scanner)}" args="${esc(scan.args)}" start="${scan.start}" version="${esc(scan.version)}">\n`;
  xml += `  <summary total="${scan.totalHosts}" up="${scan.hostsUp}" down="${scan.hostsDown}" duration="${scan.scanDuration}" />\n`;

  for (const host of hosts) {
    xml += `  <host ip="${esc(host.ip)}" ipv6="${esc(host.ipv6)}" mac="${esc(host.mac)}" hostname="${esc(host.hostname)}" status="${host.status.state}"`;
    if (host.mainOS) xml += ` os="${esc(host.mainOS)}"`;
    xml += `>\n`;
    for (const port of host.ports) {
      xml += `    <port number="${port.portid}" protocol="${esc(port.protocol)}" state="${esc(port.state.state)}"`;
      if (port.service) {
        xml += ` service="${esc(port.service.name)}"`;
        if (port.service.product) xml += ` product="${esc(port.service.product)}"`;
        if (port.service.version) xml += ` version="${esc(port.service.version)}"`;
      }
      xml += ` />\n`;
    }
    xml += `  </host>\n`;
  }

  xml += `</nmapui-export>`;
  return xml;

  function esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  }
}

function exportMarkdown(scan: NmapScan, hosts: NmapHost[], options: ExportOptions): string {
  let md = `# Nmap Scan Report\n\n`;
  md += `**Command:** \`${scan.args}\`\n`;
  md += `**Started:** ${scan.startstr}\n`;
  md += `**Duration:** ${scan.scanDuration}s\n`;
  md += `**Nmap Version:** ${scan.version}\n\n`;

  md += `## Summary\n\n`;
  md += `| Metric | Count |\n|--------|-------|\n`;
  md += `| Total Hosts | ${scan.totalHosts} |\n`;
  md += `| Hosts Up | ${scan.hostsUp} |\n`;
  md += `| Hosts Down | ${scan.hostsDown} |\n`;
  md += `| Unique Open Ports | ${scan.uniquePorts.filter(p => p.state === 'open').length} |\n`;
  md += `| Unique Services | ${scan.uniqueServices.length} |\n\n`;

  md += `## Hosts\n\n`;

  for (const host of hosts) {
    md += `### ${host.ip || host.ipv6}`;
    if (host.hostname) md += ` (${host.hostname})`;
    md += `\n\n`;

    md += `**Status:** ${host.status.state}`;
    if (host.status.reason) md += ` (${host.status.reason})`;
    md += `\n`;

    if (host.mac) {
      const vendor = host.addresses.find(a => a.addrtype === 'mac')?.vendor || '';
      md += `**MAC:** ${host.mac}${vendor ? ` (${vendor})` : ''}\n`;
    }

    if (options.includeOS && host.mainOS) {
      md += `**OS:** ${host.mainOS} (${host.os.osmatch[0]?.accuracy || 0}% accuracy)\n`;
    }

    if (options.includePorts && host.ports.length > 0) {
      const escMd = (s: string) => s.replace(/\|/g, '\\|');
      md += `\n| Port | State | Service | Product | Version |\n`;
      md += `|------|-------|---------|---------|--------|\n`;
      for (const port of host.ports) {
        md += `| ${port.portid}/${port.protocol} | ${escMd(port.state.state)} | ${escMd(port.service?.name || '-')} | ${escMd(port.service?.product || '-')} | ${escMd(port.service?.version || '-')} |\n`;
      }
    }

    if (options.includeScripts) {
      const allScripts = [
        ...host.hostscripts,
        ...host.ports.flatMap(p => p.scripts),
      ];
      if (allScripts.length > 0) {
        md += `\n**Scripts:**\n\n`;
        for (const script of allScripts) {
          md += `<details><summary>${script.id}</summary>\n\n\`\`\`\n${script.output}\n\`\`\`\n</details>\n\n`;
        }
      }
    }

    if (options.includeTrace && host.trace) {
      md += `\n**Traceroute:**\n\n`;
      md += `| TTL | RTT | IP | Host |\n|-----|-----|-------|------|\n`;
      for (const hop of host.trace.hops) {
        md += `| ${hop.ttl} | ${hop.rtt}ms | ${hop.ipaddr} | ${hop.host || '-'} |\n`;
      }
    }

    md += `\n---\n\n`;
  }

  if (options.includeNotes && options.notes && options.notes.length > 0) {
    md += `## Notes\n\n`;
    for (const note of options.notes) {
      md += `### ${note.title}\n\n`;
      if (note.targets.length > 0) {
        md += `**Targets:** ${note.targets.map(t => `\`${t.ip}${t.portId ? `:${t.portId}/${t.protocol || 'tcp'}` : ''}\``).join(', ')}\n\n`;
      }
      md += `${note.content}\n\n`;
      if (note.screenshots.length > 0) {
        md += `**Screenshots:** ${note.screenshots.map(s => s.fileName).join(', ')}\n\n`;
      }
      md += `*Created: ${new Date(note.createdAt).toISOString()} | Updated: ${new Date(note.updatedAt).toISOString()}*\n\n---\n\n`;
    }
  }

  md += `\n*Generated by NmapUI — ${new Date().toISOString()}*\n`;
  return md;
}

export function downloadExport(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
