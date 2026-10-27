const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

function timeline() {
  const source = fs.readFileSync('src/alaira_warden/static/app.js', 'utf8');
  const context = vm.createContext({ Intl, Date, setTimeout, clearTimeout });
  vm.runInContext(source.slice(0, source.indexOf('document.addEventListener("click"')) + `
    globalThis.timeline = { state, groupAgentActivity, agentTimeline };
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
  assert.match(html, /2 recorded events/);
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
  assert.match(ui.agentTimeline(Array.from({ length: 10 }, (_, index) =>
    ({ ...first, id: String(index), run_id: String(index) }))), /Show 2 earlier tasks/);
});
