import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'
import { encodeFrame, INFO_PAYLOAD, parseDeviceInfo, toHex } from '../utils/serialProtocol'
import type { DeviceInfo } from '../utils/serialProtocol'
import { SerialConnection } from '../utils/webSerial'
import type { ConnectionState, SerialApi } from '../utils/webSerial'

export interface TrafficEntry {
  id: number
  time: string
  kind: 'tx' | 'rx' | 'event' | 'error'
  text: string
  hex?: string
  size?: number
  elapsedMs?: number
}

export function useSerialConsole() {
  const support = ref<'checking' | 'available' | 'insecure' | 'unsupported'>('checking')
  const state = ref<ConnectionState>('disconnected')
  const error = ref('')
  const info = shallowRef<DeviceInfo | null>(null)
  const portInfo = shallowRef<{ usbVendorId?: number, usbProductId?: number } | null>(null)
  const logs = shallowRef<TrafficEntry[]>([])
  const pending = ref(false)
  const lastLatency = ref<number | null>(null)
  const stats = reactive({ txFrames: 0, rxFrames: 0, txBytes: 0, rxBytes: 0 })
  let client: SerialConnection | null = null
  let nextId = 0
  let alive = true
  let manualDisconnect = false

  function append(entry: Omit<TrafficEntry, 'id' | 'time'>) {
    if (!alive) return
    logs.value = [...logs.value.slice(-249), {
      ...entry, id: ++nextId,
      time: new Date().toLocaleTimeString('en-GB', {
        hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3,
      }),
    }]
  }

  function showError(cause: unknown) {
    const message = cause instanceof Error ? cause.message : String(cause)
    if (error.value !== message) append({ kind: 'error', text: message })
    error.value = message
  }

  onMounted(() => {
    const api = (navigator as Navigator & { serial?: SerialApi }).serial
    if (!window.isSecureContext) { support.value = 'insecure'; return }
    if (!api) { support.value = 'unsupported'; return }
    support.value = 'available'
    client = new SerialConnection(api, {
      state(value) {
        if (!alive) return
        state.value = value
        if (value === 'connected') Object.assign(stats, { txFrames: 0, rxFrames: 0, txBytes: 0, rxBytes: 0 })
        if (value === 'disconnected') { info.value = null; lastLatency.value = null }
      },
      port(value) { if (alive) portInfo.value = value },
      error(message) { if (alive) error.value = message },
      event(text, isError) { append({ kind: isError ? 'error' : 'event', text }) },
      bytes(direction, count) { if (alive) stats[direction === 'tx' ? 'txBytes' : 'rxBytes'] += count },
      frame(direction, payload, elapsedMs) {
        if (!alive) return
        stats[direction === 'tx' ? 'txFrames' : 'rxFrames']++
        if (elapsedMs !== undefined) lastLatency.value = elapsedMs
        append({ kind: direction, text: new TextDecoder().decode(payload), hex: toHex(encodeFrame(payload)), size: payload.length, elapsedMs })
      },
    })
  })

  onBeforeUnmount(() => { alive = false; void client?.dispose().catch(() => {}) })

  async function send(payload: Uint8Array, expectInfo = false) {
    if (!client || pending.value) return
    pending.value = true
    error.value = ''
    try {
      const response = await client.request(payload)
      if (response.text.startsWith('ERR ')) {
        throw new Error(`Firmware response: ${response.text}. This firmware currently supports public INFO only.`)
      }
      if (expectInfo) info.value = parseDeviceInfo(response.text)
      return response
    }
    catch (cause) { if (alive && !manualDisconnect) showError(cause) }
    finally { if (alive) pending.value = false }
  }

  async function requestInfo() { return send(INFO_PAYLOAD, true) }

  async function connect(baudRate: number, showAllPorts: boolean, readInfo: boolean) {
    if (!client) return
    error.value = ''
    if (await client.connect(baudRate, showAllPorts) && readInfo) await requestInfo()
  }

  async function disconnect() {
    manualDisconnect = true
    try { await client?.disconnect() }
    finally { manualDisconnect = false }
  }

  function exportLog() {
    const contents = JSON.stringify({ exportedAt: new Date().toISOString(), entries: logs.value }, null, 2)
    const url = URL.createObjectURL(new Blob([contents], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `doohickey-serial-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  return {
    support, state, error, info, portInfo, logs, pending, lastLatency, stats,
    connected: computed(() => state.value === 'connected'),
    connect, disconnect, requestInfo, send, exportLog,
    clearLog: () => { logs.value = [] },
    clearError: () => { error.value = '' },
  }
}
