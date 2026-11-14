import assert from 'node:assert/strict'
import { Context } from '@deepseek-ai/cordis'
import { ToolsService } from '@deepseek-ai/dsh-tools'

/** Real DSH admission and executable lookup, with only prompt-provider/executor boot mocked. */
export function toolRegistry() {
  const ctx = new Context()
  ctx.provide('systemPrompt', { tools() { return () => {} } })
  const service = new ToolsService(ctx)
  const definitions = new Map(), registrations = new Map()
  return {
    definitions,
    executable(name, agent, toolSet) { return service.executable(name, agent, toolSet) },
    register(definition, options = {}) {
      const entry = { definition, when: options.when }
      const unregister = service.register(definition, options)
      definitions.set(definition.name, definition); registrations.set(definition.name, entry)
      return () => {
        unregister()
        if (registrations.get(definition.name) !== entry) return
        registrations.delete(definition.name); definitions.delete(definition.name)
      }
    },
    async resolve(agent, signal = new AbortController().signal) {
      const toolSet = await service.resolve({ agent, modelSelection: {}, signal })
      return { agent, toolSet, dispose() { toolSet.dispose() } }
    },
    schemas(resolved) { return service.schemas(resolved.agent, resolved.toolSet).map(schema => schema.name).sort() },
    async execute(name, args, execution, resolved) {
      // The documented lookup for a custom executor; denies before entering tool code.
      const definition = service.executable(name, execution.agent, resolved?.toolSet)
      if (!definition) return { code: 'UNKNOWN_TOOL' }
      return definition.execute(args, execution)
    },
    assertConditional(names = [...definitions.keys()]) {
      for (const name of names) assert.equal(typeof registrations.get(name)?.when, 'function', name)
    },
  }
}

export function promptPresentation() {
  const presentation = { sections: [], contexts: [], variables: {} }
  // Catch reads as well as writes even if someone adds an undefined guard later.
  return new Proxy(presentation, {
    get(target, key) { assert.notEqual(key, 'tools', 'PromptPresentation has no tools'); return Reflect.get(target, key) },
    set(target, key, value) { assert.notEqual(key, 'tools', 'PromptPresentation has no tools'); return Reflect.set(target, key, value) },
  })
}
