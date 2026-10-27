const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

function ui() {
  const nodes = new Map();
  const context = vm.createContext({
    Intl, Date, clearTimeout, setTimeout,
    location: { hash: '#overview' },
    document: { getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, { innerHTML: '', open: false, showModal() { this.open = true; } });
      return nodes.get(id);
    } },
  });
  const source = fs.readFileSync('src/alaira_warden/static/app.js', 'utf8');
  vm.runInContext(source.slice(0, source.indexOf('document.addEventListener("click"')) + `
    globalThis.ui = { state, NAV, panorama, operationsCase, settingsPage,
      applicationsPage, applicationDetail, integrationsPage, performAction, helpDialog };
  `, context);
  return { ...context.ui, nodes };
}

test('normal operations exclude scaffold controls and preserve four navigation entries', () => {
  const app = ui();
  assert.equal(app.NAV.length, 4);
  const markup = app.panorama() + app.operationsCase();
  assert.doesNotMatch(markup, /Attempt merge|data-action="preview"|Run agent demo|3-MINUTE DEMO|data-action="prepare-patch"|data-action="validate-patch"/);
  assert.match(markup, /Investigation and response/);
  assert.match(markup, /data-view="crew"/);
});

test('sample artifacts remain explicitly synthetic without claiming a real isolated patch', () => {
  const app = ui();
  app.state.investigations = [{ id: 'case', application_id: 'app', title: 'Example',
    description: 'Guided agent demo. Synthetic sources. Sponsors not contacted.' }];
  app.state.context = { patches: [{ payload: { synthetic: true, diff: 'fixture', files: ['package-lock.json'] } }] };
  const markup = app.operationsCase();
  assert.match(markup, /Synthetic sample/);
  assert.match(markup, /Synthetic example/);
  assert.doesNotMatch(markup, />Isolated<|Attempt merge/);
  app.helpDialog();
  assert.match(app.nodes.get('modal-content').innerHTML, /Creates a labeled synthetic application/);
  assert.match(app.nodes.get('modal-content').innerHTML, /data-action="sample-run"/);
});

test('plan approval requires a human decision and an empty justification field', async () => {
  const app = ui();
  app.state.authenticated = true; app.state.database = true;
  app.state.investigations = [{ id: 'case' }];
  app.state.context = { plans: [{ content_hash: "test-plan-hash", payload: {} }] };
  await app.performAction('approve-plan', {});
  const markup = app.nodes.get('modal-content').innerHTML;
  assert.match(markup, /id="approval-form"/);
  assert.match(markup, /minlength="10"/);
  assert.match(markup, /rows="4"[^>]*><\/textarea>/);
  assert.doesNotMatch(markup, /Demo review/);
});

test('settings and deployment states reflect actual access and fetched data', () => {
  const app = ui();
  app.state.settingsTab = 'access';
  assert.match(app.settingsPage(), /Individual credentials/);
  assert.doesNotMatch(app.settingsPage(), /shared token|Development|Pending/);
  app.state.applications = [{ id: 'app', name: 'App', repository: 'owner/repo' }];
  app.state.deployments = [{ environment: 'staging', commit_sha: 'abcdef', deployed_at: '2026-10-27T12:00:00Z' }];
  assert.match(app.applicationDetail('app', 'deployments'), /staging/);
  app.state.inventoryError = 'Access denied';
  assert.match(app.applicationDetail('app', 'deployments'), /Unable to load deployments/);
  assert.doesNotMatch(app.applicationDetail('app', 'deployments'), /No deployment records/);
});
