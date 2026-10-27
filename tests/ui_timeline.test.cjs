const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

function timeline() {
  const source = fs.readFileSync('src/alaira_warden/static/app.js', 'utf8');
  const context = vm.createContext({ Intl, Date, setTimeout, clearTimeout });
  vm.runInContext(source.slice(0, source.indexOf('document.addEventListener("click"')) + `
    globalThis.timeline = { state, timelineOptions, activityTime, activityDay, activityMessage, groupActivityByRun, groupAgentActivity, groupActivityByAgent, agentTimeline };
  `, context);
  return context.timeline;
}
function event(id, status, second, run_id = 'run') {
  return { id, agent: 'scout', stage: 'sources', run_id, status,
    summary: status + ' <untrusted>', created_at: `2026-10-27T16:00:0${second}Z` };
}

test('task groups preserve retries, outcomes, elapsed time and original event details', () => {
  const ui = timeline();
  const events = [event('d', 'decided', 4), event('a', 'started', 0),
    event('b', 'failed', 1), event('c', 'started', 3)];
  const groups = ui.groupAgentActivity(events);
  assert.equal(groups.length, 2);
  assert.equal(groups[0].latest.status, 'decided');
  assert.equal(groups[1].latest.status, 'failed');
  const html = ui.agentTimeline(events);
  assert.match(html, /1.0s elapsed/);
  assert.match(html, /2 tasks · 4 recorded events/);
  assert.match(html, /Failed/);
  assert.match(html, /&lt;untrusted&gt;/);
  assert.doesNotMatch(html, /<untrusted>/);
});

test('public events and separate runs cannot be merged into a fabricated task', () => {
  const ui = timeline();
  assert.equal(ui.groupAgentActivity([event('a', 'started', 0, 'one'),
    event('b', 'decided', 1, 'two')]).length, 2);
  assert.equal(ui.groupAgentActivity([event('a', 'started', 0, null),
    event('b', 'decided', 1, null)]).length, 2);
  const first = event('a', 'started', 0);
  assert.equal(ui.groupAgentActivity([first, first]).length, 1);
  const html = ui.agentTimeline(Array.from({ length: 10 }, (_, index) =>
    ({ ...first, id: String(index), run_id: String(index) })));
  assert.equal((html.match(/<picture /g) || []).length, 10);
  assert.match(html, /1 agent · 10 events/);
  assert.equal((html.match(/class="activity-run"/g) || []).length, 10);
});

test('each agent appears once while separate tasks and case context remain inspectable', () => {
  const ui = timeline();
  const records = [event('a', 'started', 0, 'one'), event('b', 'decided', 1, 'one'),
    event('c', 'started', 2, 'two'), event('d', 'failed', 3, 'two'),
    { ...event('e', 'started', 4, 'three'), agent: 'warden' }];
  const agents = ui.groupActivityByAgent(records);
  assert.equal(agents.length, 2);
  assert.equal(agents.find((group) => group.latest.agent === 'scout').tasks.length, 2);
  const html = ui.agentTimeline(records);
  assert.equal((html.match(/<picture /g) || []).length, 3);
  assert.match(html, /2 agents · 5 events/);
  assert.match(html, /Run one/);
  assert.match(html, /Run two/);
});

test('activity uses compact native disclosure rows without nested cards or repeated status icons', () => {
  const ui = timeline();
  const html = ui.agentTimeline([event('a', 'started', 0), event('b', 'decided', 1)]);
  assert.match(html, /<details class="activity-agent" data-agent="run:run\|scout"><summary class="activity-row">/);
  assert.doesNotMatch(html, /activity-card|activity-card-header|activity-content|<article/);
  assert.doesNotMatch(html, /<details class="activity-agent"[^>]*\sopen(?:\s|>)/);
  assert.equal((html.match(/<picture /g) || []).length, 1);
  assert.match(html, /class="activity-preview"/);
  assert.match(html, /class="activity-history"/);
});

test('run grouping uses identity rather than equal timestamps and public groups stay opaque', () => {
  const ui = timeline();
  const sharedTime = [event('a', 'started', 0, 'one'), event('b', 'started', 0, 'two')];
  assert.equal(ui.groupActivityByRun(sharedTime).length, 2);
  const records = [
    { ...event('a', 'started', 0, null), activity_group: 'opaque-one', activity_group_kind: 'run' },
    { ...event('b', 'decided', 1, null), activity_group: 'opaque-one', activity_group_kind: 'run' },
    { ...event('c', 'started', 0, null), activity_group: 'opaque-two', activity_group_kind: 'case' },
  ];
  assert.equal(ui.groupActivityByRun(records).length, 2);
  assert.equal(ui.groupAgentActivity(records.slice(0, 2)).length, 1);
  const html = ui.agentTimeline(records);
  assert.match(html, /Case activity/);
  assert.equal((html.match(/<picture /g) || []).length, 2);
});

test('attention filter and order selector preserve exact run boundaries', () => {
  const ui = timeline();
  const records = [event('a', 'blocked', 1, 'old'),
    { ...event('b', 'decided', 5, 'new'), agent: 'warden' }];
  let html = ui.agentTimeline(records);
  assert.ok(html.indexOf('data-run="run:new"') < html.indexOf('data-run="run:old"'));
  assert.match(html, /Needs attention <span>\(1\)<\/span>/);
  ui.timelineOptions.order = 'oldest';
  html = ui.agentTimeline(records);
  assert.ok(html.indexOf('data-run="run:old"') < html.indexOf('data-run="run:new"'));
  ui.timelineOptions.attentionOnly = true;
  html = ui.agentTimeline(records);
  assert.match(html, /activity-attention/);
  assert.doesNotMatch(html, /data-run="run:new"/);
  assert.match(html, /aria-pressed="true"/);
});

test('relative time, English summary, source logs and sample labels are separate', () => {
  const ui = timeline();
  const now = Date.parse('2026-10-27T18:00:00Z');
  assert.match(ui.activityTime('2026-10-27T16:00:00Z', now), /2 hours ago/);
  assert.match(ui.activityTime('2026-10-27T16:00:00Z', now), /title="/);
  const item = { ...event('a', 'blocked', 0), agent: 'cartographer', synthetic: true,
    summary: 'Inventario incompleto o Zetaris falló cerrado.' };
  const html = ui.agentTimeline([item]);
  assert.match(html, /class="activity-preview">Inventory is incomplete/);
  assert.match(html, /Original record \(source language\)/);
  assert.match(html, /class="activity-sample">Sample/);
  assert.doesNotMatch(html, /CartographerSample/);
  assert.match(html, /View more/);
});
