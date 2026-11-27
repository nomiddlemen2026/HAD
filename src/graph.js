'use strict';
const { maskPhone } = require('./phone');

/**
 * Build a relationship graph from stored reports. Every edge and finding lists
 * the reports that support it. Nothing is inferred beyond what reports say:
 *  - reported_number:  a case reported this number
 *  - payment_account:  a case reported being asked to pay this account
 *  - named_together:   two numbers were named in the same report (POSSIBLE association only)
 * Findings group identifiers that appear in more than one case. A shared
 * identifier does not prove common ownership or coordination.
 */
const EDGE_LABELS = {
  reported_number: 'Reported this number',
  payment_account: 'Asked to pay this account',
  named_together: 'Named in the same report (possible association)',
};
const FINDING_LABELS = {
  same_number: 'Same reported telephone number',
  same_account: 'Same reported payment account',
  possible_association: 'Possible association',
};

const key = (type, a, b) => [type, ...[a, b].sort()].join('|');

function buildGraph(reports, { caseLabel, overrides = new Map(), includeRemoved = false }) {
  const nodes = new Map();
  const edges = new Map();
  const addNode = (id, data) => { if (!nodes.has(id)) nodes.set(id, { id, ...data }); };
  const addEdge = (type, source, target, report) => {
    const k = key(type, source, target);
    const e = edges.get(k) || { id: k, type, label: EDGE_LABELS[type], source, target, certainty: type === 'named_together' ? 'possible' : 'reported', reports: [] };
    if (!e.reports.some(r => r.id === report.id)) e.reports.push({ id: report.id, caseId: report.case_id, status: report.status, createdAt: report.created_at });
    edges.set(k, e);
  };

  const byIdentifier = new Map(); // identifier node id -> Map(caseId -> [reportIds])
  const track = (nodeId, r) => {
    const m = byIdentifier.get(nodeId) || new Map();
    const list = m.get(r.case_id) || []; if (!list.includes(r.id)) list.push(r.id);
    m.set(r.case_id, list); byIdentifier.set(nodeId, m);
  };

  for (const r of reports) {
    const caseNode = 'case:' + r.case_id;
    addNode(caseNode, { type: 'case', label: caseLabel(r) });
    const phoneNode = 'phone:' + r.phone_e164;
    addNode(phoneNode, { type: 'phone', label: r.phone_e164, masked: maskPhone(r.phone_e164) });
    addEdge('reported_number', caseNode, phoneNode, r);
    track(phoneNode, r);
    for (const acct of JSON.parse(r.related_bank_accounts || '[]')) {
      const n = 'account:' + acct;
      addNode(n, { type: 'account', label: acct });
      addEdge('payment_account', caseNode, n, r);
      track(n, r);
    }
    for (const rel of JSON.parse(r.related_phones || '[]')) {
      const n = 'phone:' + rel;
      addNode(n, { type: 'phone', label: rel, masked: maskPhone(rel) });
      addEdge('named_together', phoneNode, n, r);
    }
  }

  const findings = [];
  for (const [nodeId, cases] of byIdentifier) {
    if (cases.size < 2) continue;
    const type = nodeId.startsWith('phone:') ? 'same_number' : 'same_account';
    findings.push({
      id: type + '|' + nodeId, type, label: FINDING_LABELS[type], identifier: nodes.get(nodeId).label,
      cases: [...cases.keys()], reports: [...cases.values()].flat(),
      note: 'A shared identifier does not prove that the same person or group is behind these cases.',
    });
  }
  // A number reported as the main contact in one case and named as "another number used" in a different case.
  for (const e of edges.values()) {
    if (e.type !== 'named_together') continue;
    const edgeOverride = overrides.get(e.id);
    if (edgeOverride && edgeOverride.status === 'removed' && !includeRemoved) continue; // a removed link removes its finding
    const targetCases = byIdentifier.get(e.target);
    if (!targetCases) continue;
    const sourceCases = new Set(e.reports.map(r => r.caseId));
    const other = [...targetCases.keys()].filter(c => !sourceCases.has(c));
    if (!other.length) continue;
    findings.push({
      id: 'possible_association|' + e.id, type: 'possible_association', label: FINDING_LABELS.possible_association,
      identifier: `${nodes.get(e.source).label} ↔ ${nodes.get(e.target).label}`,
      cases: [...sourceCases, ...other], reports: [...e.reports.map(r => r.id), ...other.flatMap(c => targetCases.get(c))],
      note: 'One victim said both numbers contacted them. That does not prove one person uses both numbers.',
    });
  }

  const apply = (item) => {
    const o = overrides.get(item.id);
    if (o) item.override = { status: o.status, note: o.note, decidedAt: o.decided_at };
    return includeRemoved || !o || o.status !== 'removed';
  };
  const edgeList = [...edges.values()].filter(apply);
  const findingList = findings.filter(apply);
  // Drop nodes left without edges after removals.
  const used = new Set(edgeList.flatMap(e => [e.source, e.target]));
  return { nodes: [...nodes.values()].filter(n => used.has(n.id)), edges: edgeList, findings: findingList };
}

module.exports = { buildGraph, EDGE_LABELS, FINDING_LABELS };
