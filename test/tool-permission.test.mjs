import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { SshStore } from '../lib/store.js'
import { registerSshTools } from '../lib/tools.js'
import { toolRegistry, promptPresentation } from './tool-registry.mjs'

const terminalNames = ['ssh_terminal_open', 'ssh_terminal_send', 'ssh_terminal_read', 'ssh_terminal_signal', 'ssh_terminal_close', 'ssh_forward_start', 'ssh_forward_stop']
const mountedNames = ['ssh_list', 'ssh_set_cwd', 'ssh_exec', 'ssh_forward_list', ...terminalNames]

test('terminal-control mode rejects ssh_exec at the tool boundary', async t => {
  const fixture = await toolFixture(t, 'terminal')
  await assert.rejects(fixture.tools.get('ssh_exec').execute({ profileId: 'host-test', command: 'uptime' }, fixture.execution), /uses terminal control/)
})

test('exec mode rejects interactive terminal tools and forwards at the tool boundary', async t => {
  const fixture = await toolFixture(t, 'exec')
  await assert.rejects(fixture.tools.get('ssh_terminal_send').execute({ terminalId: 'terminal-test', text: 'uptime' }, fixture.execution), /permits one-shot commands/)
  await assert.rejects(fixture.tools.get('ssh_forward_start').execute({ ruleId: 'forward-test' }, fixture.execution), /permits one-shot commands/)
})

for (const permission of ['terminal', 'exec', undefined]) {
  test(`${permission ?? 'no injection'} mode uses step admission and tool-free PromptPresentation`, async t => {
    const fixture = await toolFixture(t, permission)
    const { registry, execution, assemble } = fixture
    registry.assertConditional(mountedNames)
    const toolSet = await registry.resolve(execution.agent)
    const admitted = registry.schemas(toolSet).filter(name => mountedNames.includes(name))
    assert.deepEqual(admitted, (permission === undefined ? [] : permission === 'terminal' ? mountedNames.filter(name => name !== 'ssh_exec') : mountedNames.filter(name => !terminalNames.includes(name))).sort())
    const presentation = promptPresentation()
    await assemble(presentation, { toolSet: toolSet.toolSet }, async () => presentation)
    assert.equal(Object.hasOwn(presentation, 'tools'), false)
    if (permission) assert.match(presentation.contexts[0].text, permission === 'terminal' ? /terminal control/ : /one-shot commands/)
    else assert.equal(presentation.contexts.length, 0)
    for (const name of mountedNames.filter(name => !admitted.includes(name))) {
      // Invalid arguments would throw if implementation were entered.
      assert.deepEqual(await registry.execute(name, null, execution, toolSet), { code: 'UNKNOWN_TOOL' })
    }
    assert.deepEqual(await registry.execute('ssh_list', {}, execution), { code: 'UNKNOWN_TOOL' })
    toolSet.dispose()
    assert.deepEqual(await registry.execute('ssh_list', {}, execution, toolSet), { code: 'UNKNOWN_TOOL' })
  })
}

test('SSH session ACL and command approval remain effective after admission', async t => {
  const fixture = await toolFixture(t, 'terminal')
  const { registry, execution, store, hooks } = fixture
  const toolSet = await registry.resolve(execution.agent)
  await assert.rejects(registry.execute('ssh_terminal_open', { profileId: 'host-other' }, execution, toolSet), /not injected/)
  await store.update(state => { state.injections[0].requireCommandApproval = true })
  const approval = hooks.get('tools/pre-execute').at(0)
  assert.equal((await approval({ name: 'ssh_terminal_send', agent: execution.agent }, async () => 'continue')).kind, 'ask')
  assert.equal(await approval({ name: 'ssh_terminal_read', agent: execution.agent }, async () => 'continue'), 'continue')
  await store.update(state => { state.injections[0].profileIds = [] })
  await assert.rejects(registry.execute('ssh_list', {}, execution, toolSet), /No SSH connection/)
  const fresh = await registry.resolve(execution.agent)
  assert.ok(!registry.schemas(fresh).some(name => mountedNames.includes(name)))
})

test('disposing registration removes admitted tools and agent listeners', async t => {
  const fixture = await toolFixture(t, 'terminal')
  const toolSet = await fixture.registry.resolve(fixture.execution.agent)
  fixture.dispose()
  assert.equal(fixture.tools.size, 0)
  assert.equal(fixture.listenerCount(), 0)
  assert.deepEqual(await fixture.registry.execute('ssh_list', {}, fixture.execution, toolSet), { code: 'UNKNOWN_TOOL' })
})

async function toolFixture(t, permission) {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-ssh-tool-mode-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const store = await SshStore.open(join(directory, 'state.json'), { allowPublicBind: false, defaultCommandTimeoutMs: 30_000, maxOutputChars: 32_000 })
  const now = Date.now()
  await store.update(state => {
    state.profiles.push({ id: 'host-test', name: 'Test', host: '127.0.0.1', port: 22, username: 'test', authType: 'agent', proxy: { type: 'none' }, keepAliveIntervalMs: 0, connectTimeoutMs: 5000, terminalType: 'xterm-256color', tags: [], createdAt: now, updatedAt: now })
    state.forwardRules.push({ id: 'forward-test', profileId: 'host-test', name: 'test', type: 'local', bindHost: '127.0.0.1', bindPort: 8080, targetHost: '127.0.0.1', targetPort: 80, autoStart: false, createdAt: now, updatedAt: now })
    if (permission) state.injections.push({ sessionId: 'session-test', profileIds: ['host-test'], permission, requireCommandApproval: false, workingDirectories: {}, workingProjectIds: {}, updatedAt: now })
  })
  const registry = toolRegistry(), hooks = new Map()
  let assemble, listeners = 0
  const agent = { session: { id: 'session-test' }, ctx: { on(name, listener) { listeners++; if (name === 'system-prompt/assemble') assemble = listener; let active = true; return () => { if (active) listeners--; active = false } } } }
  const ctx = {
    provide() { return () => {} }, tools: registry, agents: { list: () => [agent] },
    on(name, handler) { const handlers = hooks.get(name) ?? []; handlers.push(handler); hooks.set(name, handlers); return () => { const index = handlers.indexOf(handler); if (index >= 0) handlers.splice(index, 1) } },
  }
  const dispose = registerSshTools(ctx, store, {}, {}, {})
  // Explicit cleanup tests may dispose early; only invoke each disposer once.
  let disposed = false
  const close = () => { if (!disposed) { disposed = true; dispose() } }
  t.after(close)
  return { registry, tools: registry.definitions, store, hooks, assemble, dispose: close, listenerCount: () => listeners, execution: { agent, signal: new AbortController().signal } }
}
