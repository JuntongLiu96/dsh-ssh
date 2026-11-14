import assert from 'node:assert/strict'
import test from 'node:test'
import { registerSshTools } from '../lib/tools.js'
import { toolRegistry, promptPresentation } from './tool-registry.mjs'

function fixture() {
  const registry = toolRegistry(), prompts = []
  const state = { injection: { profileIds: ['host'], permission: 'terminal', fileEndpointIds: ['sftp:host', 'ftp:allowed'], filePermission: 'browse', requireCommandApproval: true }, failure: false }
  const store = { injection() { if (state.failure) throw new Error('grant lookup failed'); return state.injection }, async inheritInjection() { throw new Error('legacy lineage must never be consulted') } }
  const agent = { session: { id: 'child', header: { parentSession: 'parent' } }, ctx: { on(event, callback) { if (event === 'system-prompt/assemble') prompts.push(callback); return () => {} } } }
  const ctx = { tools: registry, provide: () => () => {}, agents: { list: () => [agent] }, on: () => () => {} }
  const unregister = registerSshTools(ctx, store, {}, {}, {}, {}, {})
  let disposed = false
  const dispose = () => { if (!disposed) { disposed = true; unregister() } }
  async function assemble(context) {
    const presentation = promptPresentation()
    for (const listener of prompts) await listener(presentation, context, async () => presentation)
    return presentation
  }
  return { registry, agent, state, dispose, assemble }
}

test('failed grant lookup fails admission closed and can retry without lineage inheritance', async t => {
  const f = fixture(); t.after(f.dispose)
  f.state.failure = true
  await assert.rejects(f.registry.resolve(f.agent), error => error.code === 'TOOL_ACTIVATION_FAILED' && error.cause.message === 'grant lookup failed')
  f.state.failure = false; f.state.injection = undefined
  const denied = await f.registry.resolve(f.agent)
  assert.deepEqual(f.registry.schemas(denied).filter(name => !['ssh_request_temporary_access', 'ssh_temporary_exec'].includes(name)), [])
})

test('cancelled step preparation never publishes a tool selection', async t => {
  const f = fixture(); t.after(f.dispose)
  const controller = new AbortController()
  const pending = f.registry.resolve(f.agent, controller.signal)
  controller.abort()
  await assert.rejects(pending, error => error.name === 'AbortError')
  await assert.rejects(f.registry.resolve(f.agent, controller.signal), error => error.name === 'AbortError')
})

test('grant changes after resolution never recommend revoked or newly unadmitted tools', async t => {
  const f = fixture(); t.after(f.dispose)
  const resolved = await f.registry.resolve(f.agent); t.after(() => resolved.dispose())
  f.state.injection.permission = 'exec'
  let text = (await f.assemble({ toolSet: resolved.toolSet })).contexts.map(context => context.text).join('\n')
  for (const name of ['ssh_terminal_open', 'ssh_terminal_send', 'ssh_terminal_read', 'ssh_forward_start', 'ssh_forward_stop', 'ssh_exec']) assert.ok(!text.includes(name), name)
  f.state.injection.profileIds = []
  f.state.injection.fileEndpointIds = ['ftp:allowed']
  text = (await f.assemble({ toolSet: resolved.toolSet })).contexts.map(context => context.text).join('\n')
  for (const name of ['ssh_list', 'file_transfer_start', 'file_transfer_cancel', 'file_download_to_local', 'file_upload_from_local']) assert.ok(!text.includes(name), name)
  assert.match(text, /file_directory_list/)
  f.state.injection = undefined
  assert.equal((await f.assemble({ toolSet: resolved.toolSet })).contexts.length, 0)
})

test('SSH and file prompt guidance follows current step selection, not durable capability alone', async t => {
  const f = fixture(); t.after(f.dispose)
  const resolved = await f.registry.resolve(f.agent)
  const full = await f.assemble({ toolSet: resolved.toolSet })
  assert.equal(full.contexts.length, 2)
  assert.match(full.contexts.find(context => context.name === 'dsh-ssh:permission-mode').text, /ssh_terminal_open/)
  assert.match(full.contexts.find(context => context.name === 'dsh-ssh:file-access').text, /file_download_to_local/)
  // A narrowed selection uses the actual current registry selection as its source.
  const narrow = {
    dispose() {},
    view(scope) { return new Map([...resolved.toolSet.view(scope)].filter(([name]) => ['ssh_list', 'file_transfer_status'].includes(name))) },
  }
  const partial = await f.assemble({ toolSet: narrow })
  assert.equal(partial.contexts.length, 2)
  const text = partial.contexts.map(context => context.text).join('\n')
  for (const name of ['ssh_terminal_open', 'ssh_terminal_send', 'ssh_terminal_read', 'ssh_exec', 'file_endpoint_list', 'file_directory_list', 'file_download_to_local', 'file_upload_from_local', 'file_transfer_start', 'file_transfer_cancel']) assert.ok(!text.includes(name), name)
  for (const context of [{}, { toolSet: (await f.registry.resolve({ session: { id: 'other' } })).toolSet }]) {
    assert.equal((await f.assemble(context)).contexts.length, 0)
  }
  resolved.dispose()
  assert.equal((await f.assemble({ toolSet: resolved.toolSet })).contexts.length, 0)
  const beforeUnload = await f.registry.resolve(f.agent)
  f.dispose()
  assert.equal((await f.assemble({ toolSet: beforeUnload.toolSet })).contexts.length, 0)
})
