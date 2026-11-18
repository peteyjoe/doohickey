<script setup lang="ts">
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { MAX_FRAME_SIZE, parseHex } from './utils/serialProtocol'

const {
  support, state, error, info, portInfo, logs, pending, lastLatency, stats,
  connected, connect, disconnect, requestInfo, send, exportLog, clearLog, clearError,
} = useSerialConsole()

const baudRate = ref(115200)
const showAllPorts = ref(false)
const readOnConnect = ref(true)
const format = ref<'text' | 'hex'>('text')
const logFormat = ref<'text' | 'hex'>('text')
const draft = reactive({ text: 'INFO', hex: '49 4e 46 4f' })
const autoScroll = ref(true)
const logPanel = ref<HTMLElement | null>(null)
const busy = computed(() => state.value !== 'disconnected' && state.value !== 'connected')
const stateLabel = computed(() => ({
  disconnected: 'Disconnected', selecting: 'Choose a port…', connecting: 'Connecting…',
  connected: 'Connected', disconnecting: 'Disconnecting…',
})[state.value])
const serialLabel = computed(() => {
  if (!portInfo.value) return 'No port selected'
  const hex = (n?: number) => n === undefined ? '—' : n.toString(16).padStart(4, '0')
  return `${hex(portInfo.value.usbVendorId)}:${hex(portInfo.value.usbProductId)}`
})
const message = computed(() => {
  try {
    const bytes = format.value === 'text' ? new TextEncoder().encode(draft.text) : parseHex(draft.hex)
    if (bytes.length < 1 || bytes.length > MAX_FRAME_SIZE) throw new Error(`Use between 1 and ${MAX_FRAME_SIZE} payload bytes.`)
    return { bytes, error: '' }
  }
  catch (cause) { return { bytes: null, error: cause instanceof Error ? cause.message : String(cause) } }
})

async function sendCustom() {
  if (!message.value.bytes || pending.value || !connected.value) return
  await send(message.value.bytes, new TextDecoder().decode(message.value.bytes) === 'INFO')
}

watch(() => logs.value.at(-1)?.id, async () => {
  if (!autoScroll.value) return
  await nextTick()
  if (logPanel.value) logPanel.value.scrollTop = logPanel.value.scrollHeight
})

const baudRates = [115200, 9600, 57600, 921600].map(value => ({ label: `${value.toLocaleString('en-US')} baud`, value }))
</script>

<template>
  <UApp>
    <NuxtRouteAnnouncer />
    <header class="site-header">
      <div class="header-inner">
        <a class="brand" href="/" aria-label="DOOHICKEY Serial Lab home">
          <span class="brand-symbol"><UIcon name="i-lucide-cpu" /></span>
          <span>DOOHICKEY<span class="brand-divider">/</span><span class="brand-secondary">Serial Lab</span></span>
        </a>
        <div class="browser-indicator">
          <span class="status-dot" :class="{ available: support === 'available' }" />
          {{ support === 'available' ? 'Web Serial available' : support === 'checking' ? 'Checking browser' : 'Web Serial unavailable' }}
        </div>
      </div>
    </header>

    <main class="workspace">
      <div class="page-heading">
        <div>
          <div class="eyebrow"><span /> HARDWARE WORKBENCH</div>
          <h1>Serial console<span class="heading-period">.</span></h1>
          <p>Connect your device. Inspect every byte.</p>
        </div>
        <div class="protocol-label"><UIcon name="i-lucide-cable" /> USB CDC ACM <span>·</span> <span class="mono">v1 framing</span></div>
      </div>

      <UAlert v-if="support === 'unsupported' || support === 'insecure'" class="notice" color="warning" variant="subtle"
        icon="i-lucide-info" :title="support === 'insecure' ? 'A secure browser context is required' : 'This browser does not support Web Serial'"
        :description="support === 'insecure' ? 'Open this page on localhost or over HTTPS, then use desktop Chrome or Edge.' : 'Use desktop Chrome or Edge on localhost or HTTPS to connect to the USB serial interface.'" />
      <div v-if="error" class="error-notice" role="alert">
        <UIcon name="i-lucide-circle-alert" /><span>{{ error }}</span>
        <UButton aria-label="Dismiss error" color="error" variant="ghost" size="xs" icon="i-lucide-x" @click="clearError" />
      </div>

      <div class="workbench-grid">
        <aside class="device-column">
          <section class="panel connection-panel" aria-labelledby="connection-title">
            <div class="panel-heading">
              <h2 id="connection-title">Connection</h2>
              <UBadge :color="connected ? 'success' : 'neutral'" variant="subtle" size="sm">
                <span class="status-dot" :class="{ available: connected, pulsing: busy }" />{{ stateLabel }}
              </UBadge>
            </div>
            <div class="connection-port">
              <div class="port-icon" :class="{ active: connected }"><UIcon name="i-lucide-usb" /></div>
              <div><strong>{{ connected ? 'USB serial device' : 'Ready when you are' }}</strong><span class="mono">{{ connected ? serialLabel : 'Native USB data port' }}</span></div>
            </div>
            <UButton v-if="!connected" class="connect-button" block size="lg" icon="i-lucide-plug"
              :disabled="support !== 'available' || busy" :loading="busy" @click="connect(baudRate, showAllPorts, readOnConnect)">
              {{ busy ? stateLabel : 'Connect device' }}
            </UButton>
            <UButton v-else class="connect-button" block size="lg" color="neutral" variant="outline" icon="i-lucide-unplug" @click="disconnect">Disconnect device</UButton>
            <div class="settings-section">
              <label for="baud-rate" class="field-label">Baud rate <span>USB line coding</span></label>
              <USelect id="baud-rate" v-model="baudRate" :items="baudRates" :disabled="state !== 'disconnected'" class="w-full" size="lg" />
              <div class="setting-row"><label for="read-on-connect">Read INFO on connect</label><USwitch id="read-on-connect" v-model="readOnConnect" :disabled="state !== 'disconnected'" size="sm" /></div>
              <div class="setting-row"><label for="all-ports">Show all serial ports</label><USwitch id="all-ports" v-model="showAllPorts" :disabled="state !== 'disconnected'" size="sm" /></div>
              <p class="filter-hint">{{ showAllPorts ? 'The picker will include other serial devices.' : 'Filtered to development device c0de:d001.' }}</p>
            </div>
            <div class="native-port-hint"><UIcon name="i-lucide-info" /><p>Use the board’s native USB connector, not the debug probe. Close other serial tools first.</p></div>
          </section>

          <section class="panel information-panel" aria-labelledby="information-title">
            <div class="panel-heading"><h2 id="information-title">Device information</h2><UButton color="neutral" variant="ghost" size="xs" icon="i-lucide-refresh-cw" aria-label="Read device info" title="Read device info" :disabled="!connected || pending" :loading="pending" @click="requestInfo" /></div>
            <template v-if="info">
              <div class="device-name"><span class="device-name-icon"><UIcon name="i-lucide-cpu" /></span><div><strong>{{ info.product }}</strong><span>USB device response</span></div><UIcon name="i-lucide-circle-check" class="device-check" /></div>
              <dl class="info-list">
                <div><dt>Firmware</dt><dd class="mono">{{ info.firmware }}</dd></div>
                <div><dt>Flash capacity</dt><dd class="mono">{{ (info.flash_bytes / 1048576).toLocaleString() }} MiB</dd></div>
                <div><dt>CTAP backend</dt><dd><span class="mini-state" :class="{ ready: info.ctap_ready }">{{ info.ctap_ready ? 'Ready' : 'Not ready' }}</span></dd></div>
                <div><dt>Authentication</dt><dd><span class="mini-state" :class="{ ready: info.authentication_ready }">{{ info.authentication_ready ? 'Ready' : 'Unavailable' }}</span></dd></div>
                <div><dt>OTP backend</dt><dd :class="{ 'test-otp': info.insecure_test_otp }">{{ info.insecure_test_otp ? 'Flash · test mode' : 'Hardware' }}</dd></div>
              </dl>
              <div v-if="info.insecure_test_otp" class="test-mode-note"><UIcon name="i-lucide-flask-conical" /> Test firmware stores OTP values in flash.</div>
            </template>
            <div v-else class="info-empty"><UIcon name="i-lucide-scan-line" /><strong>Waiting for a device</strong><p>Connect and send <code>INFO</code> to read the firmware and flash configuration.</p></div>
          </section>
          <div class="privacy-note"><UIcon name="i-lucide-monitor" /><span>Device traffic stays in this tab.<br>Logs are saved only when you export them.</span></div>
        </aside>

        <section class="panel console-panel" aria-labelledby="traffic-title">
          <div class="console-heading">
            <div class="console-title"><span class="terminal-icon"><UIcon name="i-lucide-terminal" /></span><h2 id="traffic-title">Traffic monitor</h2><span class="entry-count mono">{{ logs.length }}</span></div>
            <div class="console-actions"><UButton color="neutral" variant="ghost" size="sm" icon="i-lucide-download" :disabled="logs.length === 0" aria-label="Export log" title="Export log" @click="exportLog" /><UButton color="neutral" variant="ghost" size="sm" icon="i-lucide-trash-2" :disabled="logs.length === 0" aria-label="Clear log" title="Clear log" @click="clearLog" /></div>
          </div>
          <div class="monitor-toolbar">
            <div class="view-switch" aria-label="Traffic display"><button :class="{ selected: logFormat === 'text' }" :aria-pressed="logFormat === 'text'" @click="logFormat = 'text'">Text</button><button :class="{ selected: logFormat === 'hex' }" :aria-pressed="logFormat === 'hex'" @click="logFormat = 'hex'">Hex</button></div>
            <button class="autoscroll-control" :class="{ enabled: autoScroll }" :aria-pressed="autoScroll" @click="autoScroll = !autoScroll"><UIcon name="i-lucide-arrow-down-to-line" /> Autoscroll</button>
          </div>
          <div ref="logPanel" class="traffic-log" role="log" aria-live="polite" aria-label="Serial traffic" aria-relevant="additions">
            <div v-if="logs.length === 0" class="traffic-empty"><div class="traffic-empty-icon"><UIcon name="i-lucide-radio-tower" /></div><h3>Your connection, in plain sight.</h3><p>Connect a device to start inspecting requests and responses.</p><div class="example-frame"><span>INFO FRAME</span><code>00 04 <b>49 4e 46 4f</b></code></div></div>
            <div v-for="entry in logs" :key="entry.id" class="log-entry" :class="`log-${entry.kind}`"><time class="log-time">{{ entry.time }}</time><span class="log-kind">{{ entry.kind === 'event' ? 'SYS' : entry.kind.toUpperCase() }}</span><div class="log-message"><pre>{{ logFormat === 'hex' && entry.hex ? entry.hex : entry.text }}</pre><div v-if="entry.size !== undefined" class="log-detail">{{ entry.size }} B payload<span v-if="entry.elapsedMs !== undefined"> · {{ entry.elapsedMs.toFixed(1) }} ms</span></div></div></div>
          </div>
          <div class="monitor-stats mono"><span><i class="tx-dot" /> TX <b>{{ stats.txFrames }}</b><span class="stat-byte">{{ stats.txBytes }} B</span></span><span><i class="rx-dot" /> RX <b>{{ stats.rxFrames }}</b><span class="stat-byte">{{ stats.rxBytes }} B</span></span><span class="latency-stat"><UIcon name="i-lucide-timer" />{{ lastLatency === null ? '— ms' : `${lastLatency.toFixed(1)} ms` }}</span></div>
          <form class="composer" @submit.prevent="sendCustom">
            <div class="composer-heading"><label for="payload">Send a test message</label><div class="view-switch light" aria-label="Payload format"><button type="button" :aria-pressed="format === 'text'" :class="{ selected: format === 'text' }" @click="format = 'text'">Text</button><button type="button" :aria-pressed="format === 'hex'" :class="{ selected: format === 'hex' }" @click="format = 'hex'">Hex</button></div></div>
            <UTextarea id="payload" v-model="draft[format]" :rows="2" :maxrows="4" :spellcheck="false" class="payload-input w-full" :ui="{ base: 'font-mono' }" :placeholder="format === 'text' ? 'INFO' : '49 4e 46 4f'" aria-describedby="payload-help" @keydown.ctrl.enter.prevent="sendCustom" @keydown.meta.enter.prevent="sendCustom" />
            <div class="composer-footer"><p id="payload-help" :class="{ 'payload-error': message.error }">{{ message.error || `${message.bytes?.length ?? 0} / ${MAX_FRAME_SIZE} B · length prefix added automatically` }}</p><UButton type="submit" icon="i-lucide-arrow-up-right" :disabled="!connected || pending || !message.bytes" :loading="pending">Send message</UButton></div>
            <div class="quick-command"><span>QUICK COMMAND</span><button type="button" :disabled="!connected || pending" @click="requestInfo"><code>INFO</code><UIcon name="i-lucide-corner-down-left" /></button><span class="quick-command-note">Read public device information</span></div>
          </form>
        </section>
      </div>
      <footer class="workspace-footer"><span><UIcon name="i-lucide-circle-dot" /> Public diagnostics · authentication is not enabled in the current firmware</span><span class="mono">UINT16 BE + PAYLOAD · MAX 1040 B</span></footer>
    </main>
  </UApp>
</template>
