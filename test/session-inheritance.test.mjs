import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { SshStore } from '../lib/store.js'
import { registerSshTools } from '../lib/tools.js'
import { toolRegistry, promptPresentation } from './tool-registry.mjs'

const temporaryNames = new Set(['ssh_request_temporary_access', 'ssh_temporary_exec'])
const ordinary = names => names.filter(name => !temporaryNames.has(name))

async function fixture(t, header) {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-ssh-explicit-session-access-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const statePath = join(directory, 'state.json')
  const store = await SshStore.open(statePath, { allowPublicBind: false, defaultCommandTimeoutMs: 30_000, maxOutputChars: 32_000 })
  const now = Date.now()
  const grant = {
    sessionId: 'session-parent', profileIds: ['host-test'], fileEndpointIds: ['sftp:host-test', 'ftp:ftp-test'],
    filePermission: 'browse', requireFileApproval: true, permission: 'terminal', requireCommandApproval: true,
    workingDirectories: { 'host-test': '/srv/project' }, workingProjectIds: { 'host-test': 'project-test' }, updatedAt: now,
  }
  await store.update(state => {
    state.profiles.push({ id: 'host-test', name: 'Test', host: '127.0.0.1', port: 22, username: 'test', authType: 'agent', proxy: { type: 'none' }, keepAliveIntervalMs: 0, connectTimeoutMs: 5000, terminalType: 'xterm-256color', tags: [], createdAt: now, updatedAt: now })
    state.ftpProfiles.push({ id: 'ftp-test', name: 'Files', protocol: 'ftps-explicit', host: '127.0.0.1', port: 21, username: 'test', proxy: { type: 'none' }, initialPath: '/', connectTimeoutMs: 5000, createdAt: now, updatedAt: now })
    state.remoteProjects.push({ id: 'project-test', profileId: 'host-test', name: 'Project', path: '/srv/project', createdAt: now, updatedAt: now })
    state.injections.push(grant)
  })
  let inheritanceCalls = 0
  store.inheritInjection = async () => { inheritanceCalls++; throw new Error('tool registration must never inherit by lineage') }
  const prompts = [], hooks = new Map()
  const agent = { session: { id: 'session-child', header }, ctx: { on(name, listener) { if (name === 'system-prompt/assemble') prompts.push(listener); return () => {} } } }
  const registry = toolRegistry()
  const ctx = {
    provide() { return () => {} }, tools: registry, agents: { list: () => [agent] },
    on(name, handler) { const handlers = hooks.get(name) ?? []; handlers.push(handler); hooks.set(name, handlers); return () => {} },
  }
  const dispose = registerSshTools(ctx, store, {}, {}, {}, {}, {})
  t.after(dispose)
  async function assemble(resolved) {
    const presentation = promptPresentation()
    for (const listener of prompts) await listener(presentation, { toolSet: resolved.toolSet }, async () => presentation)
    return presentation
  }
  return { agent, registry, store, statePath, grant, assemble, hooks, inheritanceCalls: () => inheritanceCalls }
}

for (const [kind, header] of [
  ['current ordinary fork (no legacy lineage header)', {}],
  ['legacy parentSession header', { parentSession: 'session-parent' }],
  ['subagent lineage', { origin: 'subagent', parentSession: 'session-parent' }],
]) {
  test(`${kind} does not automatically acquire parent SSH or file grants`, async t => {
    const f = await fixture(t, header)
    for (let step = 0; step < 2; step++) {
      const resolved = await f.registry.resolve(f.agent)
      assert.deepEqual(ordinary(f.registry.schemas(resolved)), [])
      assert.equal((await f.assemble(resolved)).contexts.length, 0)
      assert.equal(f.store.injection('session-child'), undefined)
      resolved.dispose()
    }
    for (const handler of f.hooks.get('agent/created') ?? []) await handler({ agent: f.agent })
    assert.equal(f.inheritanceCalls(), 0)
  })
}

test('explicit durable child grant remains available, but deleting it cannot restore parent authorization', async t => {
  // Legacy metadata is deliberately supplied as hostile/stale input, not as an rc.3 fork API.
  const f = await fixture(t, { parentSession: 'session-parent' })
  await f.store.update(state => { state.injections.push({ ...f.grant, sessionId: 'session-child' }) })
  const allowed = await f.registry.resolve(f.agent)
  const names = f.registry.schemas(allowed)
  assert.ok(names.includes('ssh_terminal_open')); assert.ok(names.includes('file_transfer_start')); assert.ok(!names.includes('ssh_exec'))
  assert.equal((await f.assemble(allowed)).contexts.length, 2)
  const explicit = f.store.injection('session-child')
  assert.equal(explicit.requireCommandApproval, true); assert.equal(explicit.requireFileApproval, true)
  assert.equal(explicit.filePermission, 'browse')
  assert.deepEqual(explicit.workingDirectories, { 'host-test': '/srv/project' })
  assert.deepEqual(explicit.workingProjectIds, { 'host-test': 'project-test' })
  // Same durable deletion as api.ts DELETE injection; no tombstone or guessed provenance needed.
  await f.store.update(state => { state.injections = state.injections.filter(item => item.sessionId !== 'session-child') })
  const execution = { agent: f.agent, signal: new AbortController().signal }
  await assert.rejects(f.registry.execute('ssh_list', {}, execution, allowed), /No SSH connection/)
  await assert.rejects(f.registry.execute('file_endpoint_list', {}, execution, allowed), /No remote file endpoint/)
  for (let step = 0; step < 2; step++) {
    const denied = await f.registry.resolve(f.agent)
    assert.deepEqual(ordinary(f.registry.schemas(denied)), [])
    for (const name of ['ssh_list', 'ssh_terminal_open', 'file_endpoint_list', 'file_transfer_start']) {
      assert.deepEqual(await f.registry.execute(name, null, execution, denied), { code: 'UNKNOWN_TOOL' })
    }
    assert.equal((await f.assemble(denied)).contexts.length, 0)
    denied.dispose()
  }
  for (const handler of f.hooks.get('agent/created') ?? []) await handler({ agent: f.agent })
  assert.equal(f.store.injection('session-child'), undefined)
  assert.ok(f.store.injection('session-parent'))
  assert.equal(f.inheritanceCalls(), 0)
  const reopened = await SshStore.open(f.statePath, f.store.settings())
  assert.equal(reopened.injection('session-child'), undefined)
})
