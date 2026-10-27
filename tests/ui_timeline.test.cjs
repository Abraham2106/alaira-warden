const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

function timeline() {
  const source = fs.readFileSync('src/alaira_warden/static/app.js', 'utf8');
  const context = vm.createContext({ Intl, Date, setTimeout, clearTimeout });
  vm.runInContext(source.slice(0, source.indexOf('document.addEventListener("click"')) + `
    globalThis.timeline = { state, groupAgentActivity, groupActivityByAgent, agentTimeline };
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
  assert.equal((html.match(/<picture /g) || []).length, 1);
  assert.match(html, /1 agent · 10 events/);
  assert.match(html, /10 tasks · 10 recorded events/);
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
  assert.equal((html.match(/<picture /g) || []).length, 2);
  assert.match(html, /2 agents · 5 events/);
  assert.match(html, /Run one/);
  assert.match(html, /Run two/);
});

test('activity uses compact native disclosure rows without nested cards or repeated status icons', () => {
  const ui = timeline();
  const html = ui.agentTimeline([event('a', 'started', 0), event('b', 'decided', 1)]);
  assert.match(html, /<details class="activity-agent" data-agent="scout"><summary class="activity-row">/);
  assert.doesNotMatch(html, /activity-card|activity-card-header|activity-content|<article/);
  assert.doesNotMatch(html, /<details[^>]*\sopen(?:\s|>)/);
  assert.equal((html.match(/<picture /g) || []).length, 1);
  assert.match(html, /class="activity-preview"/);
  assert.match(html, /class="activity-history"/);
});
