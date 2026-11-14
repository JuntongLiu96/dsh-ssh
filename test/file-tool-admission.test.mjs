import assert from 'node:assert/strict'
import test from 'node:test'
import { registerFileTransferTools } from '../lib/file-transfer-tools.js'
import { toolRegistry, promptPresentation } from './tool-registry.mjs'

function fixture(injection) {
  const registry = toolRegistry(), hooks = new Map(), prompts = new Map()
  const state = { injection }, calls = { connect: 0, start: 0, get: [], cancel: [] }
  const agent = { session: { id: 'owner', header: {} }, ctx: { on(event, handler) { prompts.set(event, handler); return () => prompts.delete(event) } } }
  const store = { injection(id) { return id === 'owner' ? state.injection : undefined } }
  const ctx = { tools: registry, agents: { list: () => [agent] }, on(event, handler) { hooks.set(event, handler); return () => hooks.delete(event) } }
  const files = {
    endpoint(id) { return { id, name: id } },
    async connect() { calls.connect++; return { async list() { return [] }, close() {} } },
  }
  const transfers = {
    start() { calls.start++; return { id: 'job' } },
    get(id, owner) { calls.get.push([id, owner]); return { id } },
    cancel(id, owner) { calls.cancel.push([id, owner]); return true },
  }
  const dispose = registerFileTransferTools(ctx, store, files, transfers)
  return { registry, agent, hooks, prompts, state, calls, dispose, exec: { agent, signal: new AbortController().signal } }
}

const transferNames = ['file_transfer_start', 'file_transfer_cancel', 'file_download_to_local', 'file_upload_from_local']
for (const permission of ['browse', 'transfer', undefined]) {
  test(`FTP ${permission ?? 'no grant'} admission rejects disabled calls without entering implementation`, async t => {
    const fixtureData = fixture(permission ? { sessionId: 'owner', profileIds: [], fileEndpointIds: ['ftp:allowed'], filePermission: permission, requireFileApproval: true } : undefined)
    t.after(fixtureData.dispose)
    const { registry, agent, exec, prompts, calls } = fixtureData
    registry.assertConditional()
    const toolSet = await registry.resolve(agent)
    const names = registry.schemas(toolSet)
    assert.equal(names.length, permission === undefined ? 0 : permission === 'browse' ? 3 : 7)
    const denied = permission === undefined ? [...registry.definitions.keys()] : permission === 'browse' ? transferNames : []
    for (const name of denied) assert.deepEqual(await registry.execute(name, null, exec, toolSet), { code: 'UNKNOWN_TOOL' })
    assert.equal(calls.connect, 0); assert.equal(calls.start, 0); assert.equal(calls.cancel.length, 0)
    const presentation = promptPresentation()
    await prompts.get('system-prompt/assemble')(presentation, { toolSet: toolSet.toolSet }, async () => presentation)
    assert.equal(presentation.contexts.length, permission ? 1 : 0)
    const promptText = presentation.contexts.map(context => context.text).join('\n')
    for (const name of denied) assert.ok(!promptText.includes(name), `prompt must not recommend unadmitted ${name}`)
    if (permission === 'browse') assert.match(promptText, /browsing and transfer-status inspection only/)
    if (permission === 'transfer') for (const name of transferNames) assert.ok(promptText.includes(name))
    for (const context of [{}, { toolSet: (await registry.resolve({ session: { id: 'other' } })).toolSet }]) {
      const hidden = promptPresentation()
      await prompts.get('system-prompt/assemble')(hidden, context, async () => hidden)
      assert.equal(hidden.contexts.length, 0)
    }
    assert.deepEqual(await registry.execute('file_endpoint_list', {}, exec), { code: 'UNKNOWN_TOOL' })
    toolSet.dispose()
    assert.deepEqual(await registry.execute('file_endpoint_list', {}, exec, toolSet), { code: 'UNKNOWN_TOOL' })
  })
}

test('mixed mounted SFTP / browse-only FTP retains endpoint ACL, approval and transfer ownership', async t => {
  const fixtureData = fixture({ sessionId: 'owner', profileIds: ['host'], fileEndpointIds: ['sftp:host', 'ftp:allowed'], filePermission: 'browse', requireCommandApproval: true, requireFileApproval: false })
  t.after(fixtureData.dispose)
  const { registry, agent, exec, hooks, state, calls } = fixtureData
  const toolSet = await registry.resolve(agent)
  assert.equal(registry.schemas(toolSet).length, 7)
  const approval = hooks.get('tools/pre-execute')
  assert.equal((await approval({ name: 'file_download_to_local', agent, arguments: { endpointId: 'sftp:host' } }, async () => 'continue')).kind, 'ask')
  assert.equal(await approval({ name: 'file_download_to_local', agent, arguments: { endpointId: 'ftp:allowed' } }, async () => 'continue'), 'continue')
  const request = { sourceEndpointId: 'sftp:host', sourcePaths: ['/a'], destinationEndpointId: 'ftp:allowed', destinationDirectory: '/b' }
  await assert.rejects(registry.execute('file_transfer_start', request, exec, toolSet), /only permits remote file browsing for this endpoint/)
  await assert.rejects(registry.execute('file_directory_list', { endpointId: 'ftp:hidden', path: '/' }, exec, toolSet), /not authorized/)
  await assert.rejects(registry.execute('file_download_to_local', { endpointId: 'ftp:allowed', remotePath: '/a' }, exec, toolSet), /only permits/)
  await assert.rejects(registry.execute('file_upload_from_local', { endpointId: 'ftp:allowed', localPath: 'a', remoteDirectory: '/' }, exec, toolSet), /only permits/)
  assert.equal(calls.start, 0); assert.equal(calls.connect, 0)
  await registry.execute('file_transfer_status', { jobId: 'job' }, exec, toolSet)
  await registry.execute('file_transfer_cancel', { jobId: 'job' }, exec, toolSet)
  assert.deepEqual(calls.get, [['job', 'owner']]); assert.deepEqual(calls.cancel, [['job', 'owner']])
  const other = { agent: { session: { id: 'other', header: {} } }, signal: exec.signal }
  assert.deepEqual(await registry.execute('file_transfer_cancel', { jobId: 'job' }, other, toolSet), { code: 'UNKNOWN_TOOL' })
  state.injection.profileIds = []; state.injection.fileEndpointIds = ['ftp:allowed']
  const browseSet = await registry.resolve(agent)
  assert.ok(!registry.schemas(browseSet).includes('file_transfer_start'))
  // A snapshot admitted earlier must still respect later revocation in the body.
  await assert.rejects(registry.execute('file_transfer_cancel', { jobId: 'job' }, exec, toolSet), /only permits remote file browsing/)
  state.injection = undefined
  await assert.rejects(registry.execute('file_transfer_status', { jobId: 'job' }, exec, toolSet), /No remote file endpoint/)
})

test('file cleanup unregisters declarations, approval and scoped prompt callbacks', async () => {
  const { registry, agent, exec, hooks, prompts, dispose } = fixture({ sessionId: 'owner', profileIds: [], fileEndpointIds: ['ftp:allowed'], filePermission: 'transfer' })
  const toolSet = await registry.resolve(agent)
  assert.equal(registry.definitions.size, 7)
  dispose()
  assert.equal(registry.definitions.size, 0); assert.equal(hooks.size, 0); assert.equal(prompts.size, 0)
  assert.deepEqual(await registry.execute('file_endpoint_list', {}, exec, toolSet), { code: 'UNKNOWN_TOOL' })
})
