import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { EventEmitter, once } from 'node:events'
import test from 'node:test'
import ssh2 from 'ssh2'
import { SshConnector, HostKeyRequiredError } from '../lib/connector.js'

const password = 'dummy-only-$正确-password'
const { privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
})
const fingerprint = 'SHA256:' + createHash('sha256').update(ssh2.utils.parseKey(privateKey).getPublicSSH()).digest('hex')
const base = {
  id: 'mock', name: 'Mock', host: '127.0.0.1', username: 'root', authType: 'password',
  proxy: { type: 'none' }, connectTimeoutMs: 3000, keepAliveIntervalMs: 0,
  hostFingerprint: fingerprint,
}

async function fixture(t, authenticate) {
  const clients = new Set()
  const attempts = []
  const server = new ssh2.Server({ hostKeys: [privateKey] }, client => {
    clients.add(client)
    client.on('close', () => clients.delete(client))
    client.on('error', () => {})
    client.on('authentication', context => {
      attempts.push(context.method)
      authenticate(context)
    })
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  t.after(async () => {
    for (const client of clients) client.end()
    await new Promise(resolve => server.close(resolve))
  })
  return { profile: { ...base, port: server.address().port }, attempts }
}

function draft(profile, secrets = { password }, signal) {
  return new SshConnector({ groupProxies: () => [] }, {}).connectDraft(profile, secrets, signal)
}

// Mirrors Debian OpenSSH advertising publickey,keyboard-interactive, not password.
test('password fallback succeeds against keyboard-interactive-only server', async t => {
  const replies = []
  const { profile, attempts } = await fixture(t, ctx => {
    if (ctx.method !== 'keyboard-interactive') return ctx.reject(['publickey', 'keyboard-interactive'])
    ctx.prompt([{ prompt: 'Password: ', echo: false }], answers => {
      replies.push(answers)
      if (ctx.username === 'root' && answers[0] === password) ctx.accept()
      else ctx.reject(['keyboard-interactive'])
    })
  })
  const connections = await Promise.all([draft(profile), draft(profile)])
  for (const connection of connections) connection.close()
  assert.deepEqual(replies, [[password], [password]], 'each connection has its own guard')
  assert.equal(attempts.filter(method => method === 'keyboard-interactive').length, 2)
})

test('ordinary password authentication is unchanged', async t => {
  const { profile, attempts } = await fixture(t, ctx => {
    if (ctx.method === 'password' && ctx.password === password) ctx.accept()
    else ctx.reject(['password'])
  })
  const connection = await draft(profile)
  connection.close()
  assert.deepEqual(attempts, ['none', 'password'])
})

test('zero-prompt informational rounds before and after password succeed', async t => {
  const replies = []
  const { profile } = await fixture(t, ctx => {
    if (ctx.method !== 'keyboard-interactive') return ctx.reject(['keyboard-interactive'])
    ctx.prompt([], before => {
      replies.push(before)
      ctx.prompt([{ prompt: 'PASSWORD:\t', echo: false }], answer => {
        replies.push(answer)
        ctx.prompt([], after => { replies.push(after); ctx.accept() })
      })
    })
  })
  const connection = await draft(profile)
  connection.close()
  assert.deepEqual(replies, [[], [password], []])
})

for (const prompt of ['Verification code:', 'Passcode:', 'New password:', 'Current password:', "root's password:", 'Password\n:', 'Password:\n', 'Password:\r', 'Password:\r\n', 'Password: extra']) {
  test(`unsupported prompt ${JSON.stringify(prompt)} fails without a reply`, async t => {
    let answered = false
    const { profile } = await fixture(t, ctx => {
      if (ctx.method !== 'keyboard-interactive') return ctx.reject(['keyboard-interactive'])
      ctx.prompt([{ prompt, echo: false }], () => { answered = true; ctx.accept() })
    })
    await assert.rejects(draft(profile), { code: 'SSH_INTERACTIVE_UNSUPPORTED' })
    assert.equal(answered, false)
  })
}

for (const prompts of [
  [{ prompt: 'Password:', echo: true }],
  [{ prompt: 'Password:', echo: false }, { prompt: 'Verification code:', echo: false }],
]) {
  test(`visible or multi-prompt challenge fails without partial response: ${JSON.stringify(prompts)}`, async t => {
    let answered = false
    const { profile } = await fixture(t, ctx => {
      if (ctx.method !== 'keyboard-interactive') return ctx.reject(['keyboard-interactive'])
      ctx.prompt(prompts, () => { answered = true; ctx.accept() })
    })
    await assert.rejects(draft(profile), { code: 'SSH_INTERACTIVE_UNSUPPORTED' })
    assert.equal(answered, false)
  })
}

for (const second of ['Password:', 'Verification code:', 'New password:']) {
  test(`a second ${second} challenge never receives another secret`, async t => {
    const replies = []
    const { profile } = await fixture(t, ctx => {
      if (ctx.method !== 'keyboard-interactive') return ctx.reject(['keyboard-interactive'])
      ctx.prompt([{ prompt: 'Password:', echo: false }], answer => {
        replies.push(answer)
        ctx.prompt([{ prompt: second, echo: false }], extra => { replies.push(extra); ctx.accept() })
      })
    })
    await assert.rejects(draft(profile), { code: 'SSH_INTERACTIVE_UNSUPPORTED' })
    assert.deepEqual(replies, [[password]])
  })
}

test('wrong password remains an authentication error, not a host-key error', async t => {
  const { profile } = await fixture(t, ctx => {
    if (ctx.method !== 'keyboard-interactive') return ctx.reject(['keyboard-interactive'])
    ctx.prompt([{ prompt: 'Password:', echo: false }], () => ctx.reject(['keyboard-interactive']))
  })
  await assert.rejects(draft(profile, { password: 'wrong' }), error => {
    assert.equal(error instanceof HostKeyRequiredError, false)
    assert.match(error.message, /All configured authentication methods failed/)
    return true
  })
})

test('untrusted or changed fingerprint blocks before authentication', async t => {
  let authenticated = false
  const { profile } = await fixture(t, ctx => { authenticated = true; ctx.reject() })
  for (const hostFingerprint of [undefined, 'SHA256:' + '0'.repeat(64)]) {
    await assert.rejects(draft({ ...profile, hostFingerprint }), HostKeyRequiredError)
  }
  assert.equal(authenticated, false)
  assert.equal(profile.hostFingerprint, fingerprint)
})

test('abort while an interactive challenge is held closes the connection', async t => {
  const events = new EventEmitter()
  const held = once(events, 'held')
  const { profile } = await fixture(t, ctx => {
    if (ctx.method !== 'keyboard-interactive') return ctx.reject(['keyboard-interactive'])
    events.emit('held')
  })
  const controller = new AbortController()
  const pending = draft(profile, { password }, controller.signal)
  const rejected = assert.rejects(pending, /cancelled by test/)
  await held
  controller.abort(new Error('cancelled by test'))
  await rejected
})

test('timeout during interactive authentication settles promptly', async t => {
  const { profile } = await fixture(t, ctx => {
    if (ctx.method !== 'keyboard-interactive') ctx.reject(['keyboard-interactive'])
  })
  await assert.rejects(draft({ ...profile, connectTimeoutMs: 500 }), /Timed out while waiting for handshake/)
})

// Exercise defensive branches ssh2 normally handles internally, and listener lifecycle.
test('synthetic challenges enforce hidden prompt, empty rounds, and settlement guards', async () => {
  const OriginalClient = ssh2.Client
  let client
  class FakeClient extends EventEmitter {
    config
    destroyed = false
    connect(config) { this.config = config; client = this }
    destroy() { this.destroyed = true; this.emit('close') }
    end() { this.emit('close') }
  }
  ssh2.Client = FakeClient
  try {
    let pending = draft(base)
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(client.config.tryKeyboard, true)
    const replies = []
    const listener = client.listeners('keyboard-interactive')[0]
    listener('', '', '', [], answers => replies.push(answers))
    listener('', '', '', [{ prompt: 'Password:', echo: false }], answers => replies.push(answers))
    listener('', '', '', [], answers => replies.push(answers))
    client.emit('ready')
    const connection = await pending
    assert.equal(client.listenerCount('keyboard-interactive'), 0)
    listener('', '', '', [{ prompt: 'Password:', echo: false }], answers => replies.push(answers))
    assert.deepEqual(replies, [[], [password], []])
    connection.close()

    for (const echo of [undefined, true]) {
      pending = draft(base)
      const rejected = assert.rejects(pending, { code: 'SSH_INTERACTIVE_UNSUPPORTED' })
      await new Promise(resolve => setImmediate(resolve))
      client.emit('keyboard-interactive', '', '', '', [{ prompt: 'Password:', echo }], () => assert.fail('must not answer'))
      await rejected
      assert.equal(client.destroyed, true)
    }
    pending = draft(base)
    const rejected = assert.rejects(pending, /callback failed/)
    await new Promise(resolve => setImmediate(resolve))
    client.emit('keyboard-interactive', '', '', '', [{ prompt: 'Password:', echo: false }], () => { throw new Error('callback failed') })
    await rejected

    pending = draft(base)
    const changed = assert.rejects(pending, { code: 'SSH_PASSWORD_CHANGE_REQUIRED' })
    await new Promise(resolve => setImmediate(resolve))
    client.emit('change password', 'ignored', () => assert.fail('must not change password'))
    await changed

    pending = draft({ ...base, authType: 'private-key' }, { privateKey, password })
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(client.config.tryKeyboard, undefined)
    assert.equal(client.listenerCount('keyboard-interactive'), 0)
    client.emit('ready')
    ;(await pending).close()
  } finally {
    ssh2.Client = OriginalClient
  }
})
