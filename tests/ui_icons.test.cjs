const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

test('all crew and connector assets resolve locally and motion can be paused', () => {
  const source = fs.readFileSync('src/alaira_warden/static/app.js', 'utf8');
  const context = vm.createContext({ Intl, Date, setTimeout, clearTimeout });
  vm.runInContext(source.slice(0, source.indexOf('document.addEventListener("click"')) + `
    globalThis.icons = { state, AGENT_AVATARS, CONNECTOR_ASSETS, agentAvatar, connectorIcon,
      agentTimeline, agentsPage, motionControl, pause() { agentMotionPaused = true; } };
  `, context);
  const ui = context.icons;
  for (const id of Object.keys(ui.AGENT_AVATARS)) {
    const markup = ui.agentAvatar(id);
    assert.match(markup, /prefers-reduced-motion: reduce/);
    for (const match of markup.matchAll(/(?:src|srcset)="([^"]+)"/g)) {
      assert.ok(fs.existsSync('src/alaira_warden' + match[1]), match[1]);
    }
  }
  for (const id of Object.keys(ui.CONNECTOR_ASSETS)) {
    const path = ui.connectorIcon(id).match(/src="([^"]+)"/)[1];
    assert.ok(fs.existsSync('src/alaira_warden' + path), path);
  }
  assert.doesNotMatch(ui.connectorIcon('cisa-kev'), /<img/); // semantic shield, not invented logo
  ui.state.crew = [{ id: 'warden', name: 'Warden', role: 'orchestrator', tools: [] }];
  const timeline = ui.agentTimeline([{ agent: 'warden', status: 'started', stage: 'sources' }]);
  assert.match(timeline, /agent-avatar-compact/);
  assert.match(timeline, />Warden<|>started</);
  assert.match(ui.agentsPage(), /agent-avatar/);
  ui.pause();
  assert.doesNotMatch(ui.agentAvatar('warden'), /src="[^"]*\/ink\.svg"/);
  assert.match(ui.motionControl(), /aria-pressed="true"/);
});
