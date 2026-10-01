import { useEffect, useRef, useState } from 'react'
import logo from '../../Images/Avantis-logo-prl.png'
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowRight, Check, ChevronDown,
  CircleHelp, Clock3, FileUp, Fingerprint, Gauge, Globe2, KeyRound, ListFilter,
  LockKeyhole, Plus, Search, Shield, ShieldAlert, ShieldCheck, Trash2, Upload,
  X,
} from 'lucide-react'

const pages = [
  { id: 'protect', label: 'Protection' },
  { id: 'import', label: 'Import domains' },
  { id: 'domains', label: 'Blocked domains' },
  { id: 'insights', label: 'Insights & rules' },
]

const retentionOptions = [
  { label: '1 hour', hours: 1 },
  { label: '24 hours', hours: 24 },
  { label: '7 days', hours: 168 },
]

function App() {
  const [apiReady, setApiReady] = useState(Boolean(window.pywebview?.api))
  const [bridgeTimedOut, setBridgeTimedOut] = useState(false)
  const [state, setState] = useState(null)
  const [startupError, setStartupError] = useState('')
  const [page, setPage] = useState('protect')
  const [analysisInput, setAnalysisInput] = useState('')
  const [analysis, setAnalysis] = useState(null)
  const [addInput, setAddInput] = useState('')
  const [bulkInput, setBulkInput] = useState('')
  const [domainQuery, setDomainQuery] = useState('')
  const [selectedDomains, setSelectedDomains] = useState([])
  const [insightTab, setInsightTab] = useState('activity')
  const [dictionary, setDictionary] = useState([])
  const [dictionaryQuery, setDictionaryQuery] = useState('')
  const [ruleQuery, setRuleQuery] = useState('')
  const [newCategory, setNewCategory] = useState('gambling')
  const [newKeyword, setNewKeyword] = useState('')
  const [selectedRules, setSelectedRules] = useState([])
  const [adminPanel, setAdminPanel] = useState(false)
  const [modal, setModal] = useState(null)
  const modalResolver = useRef(null)
  const [toast, setToast] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const ready = () => {
      if (window.pywebview?.api) {
        setApiReady(true)
        setBridgeTimedOut(false)
        window.clearInterval(pollId)
        window.clearTimeout(timeoutId)
      }
    }
    const pollId = window.setInterval(ready, 100)
    const timeoutId = window.setTimeout(() => setBridgeTimedOut(true), 15000)
    window.addEventListener('pywebviewready', ready)
    ready()
    return () => {
      window.removeEventListener('pywebviewready', ready)
      window.clearInterval(pollId)
      window.clearTimeout(timeoutId)
    }
  }, [])

  useEffect(() => {
    if (!apiReady) return
    refreshState().catch(showError)
  }, [apiReady])

  useEffect(() => {
    if (!toast) return
    const timeout = window.setTimeout(() => setToast(null), 3600)
    return () => window.clearTimeout(timeout)
  }, [toast])

  const safeMode = state?.protection_profile === 'child_protection'
  const hostsStatusMessage = state?.hosts_status?.[0] || ''
  const hostsStatusLevel = state?.hosts_status?.[1] || 'warning'
  const hostsActive = /\d+ Avantis hostnames in \d+ mappings\./.test(hostsStatusMessage)
  const hostsStatusLabel = hostsActive
    ? 'Hosts protection active'
    : hostsStatusLevel === 'error'
      ? 'Hosts file unavailable'
      : hostsStatusMessage.includes('Incomplete Avantis markers')
        ? 'Hosts file needs review'
        : 'Hosts rules not applied'
  const hiddenPages = safeMode ? pages.filter((item) => item.id === 'protect') : pages
  const shownDomains = (state?.blocked_domains || []).filter((domain) => domain.includes(domainQuery.trim().toLowerCase()))

  async function refreshState() {
    let timeoutId
    try {
      const next = await Promise.race([
        window.pywebview.api.get_state(),
        new Promise((_, reject) => {
          timeoutId = window.setTimeout(() => reject(new Error('Python get_state call timed out after 10 seconds.')), 10000)
        }),
      ])
      setState(next)
      setStartupError('')
      setSelectedDomains((selected) => selected.filter((domain) => next.blocked_domains.includes(domain)))
      return next
    } catch (error) {
      setStartupError(error?.message || String(error))
      throw error
    } finally {
      window.clearTimeout(timeoutId)
    }
  }

  function showError(error) {
    setToast({ type: 'error', message: error?.message || String(error) })
  }

  async function perform(action, successMessage, onSuccess) {
    setBusy(true)
    try {
      const result = await action()
      if (result?.state) setState(result.state)
      if (onSuccess) await onSuccess(result)
      else if (result?.blocked_domains) setState(result)
      else await refreshState()
      if (successMessage) setToast({ type: 'success', message: successMessage })
      return result
    } catch (error) {
      showError(error)
      return null
    } finally {
      setBusy(false)
    }
  }

  function ask(title, description, options = {}) {
    return new Promise((resolve) => {
      modalResolver.current = resolve
      setModal({ title, description, value: '', ...options })
    })
  }

  function closeModal(value) {
    modalResolver.current?.(value)
    modalResolver.current = null
    setModal(null)
  }

  async function writePassword(action) {
    if (!safeMode || !state?.has_profile_password) return ''
    return ask('Admin password required', `Enter the admin password to ${action}.`, { secure: true })
  }

  async function analyze() {
    if (!analysisInput.trim()) {
      setToast({ type: 'error', message: 'Enter a website or domain to analyze.' })
      return
    }
    const result = await perform(
      () => window.pywebview.api.analyze_site(analysisInput.trim()),
      null,
      async (value) => {
        setAnalysis(value)
        await refreshState()
      },
    )
    if (result && !result.domain) setToast({ type: 'error', message: 'Enter a valid website or domain.' })
  }

  async function addDomains(value, clearInput) {
    const password = await writePassword('add domains in Safe Mode')
    if (password === null) return
    const result = await perform(
      () => window.pywebview.api.add_domains(value, password),
      null,
      async (response) => {
        setState(response.state)
        setToast({ type: 'success', message: `${response.added.length} domain${response.added.length === 1 ? '' : 's'} added.` })
        clearInput?.()
      },
    )
    return result
  }

  async function importFile() {
    const password = await writePassword('import domains in Safe Mode')
    if (password === null) return
    await perform(
      () => window.pywebview.api.import_file(password),
      null,
      async (result) => {
        setState(result.state)
        if (result.added.length) setToast({ type: 'success', message: `${result.added.length} domains imported${result.source ? ` from ${result.source}` : ''}.` })
        else setToast({ type: 'info', message: 'Import cancelled.' })
      },
    )
  }

  async function removeSelected() {
    const password = await writePassword('remove domains in Safe Mode')
    if (password === null) return
    await perform(
      () => window.pywebview.api.remove_domains(selectedDomains, password),
      `${selectedDomains.length} domain${selectedDomains.length === 1 ? '' : 's'} removed.`,
      async (next) => {
        setState(next)
        setSelectedDomains([])
      },
    )
  }

  async function clearDomains() {
    const confirmed = await ask('Clear all blocked domains?', 'This removes every domain from the local block list.', { confirm: true, confirmLabel: 'Clear domains' })
    if (!confirmed) return
    const password = await writePassword('clear the blocked list in Safe Mode')
    if (password === null) return
    await perform(() => window.pywebview.api.clear_domains(password), 'Blocked domain list cleared.')
    setSelectedDomains([])
  }

  async function changeProfile(profile) {
    let password = ''
    let newPassword = ''
    if (state?.has_profile_password) {
      password = await ask('Admin password', 'Enter the admin password to change the protection mode.', { secure: true })
      if (password === null) return
    }
    if (profile === 'child_protection' && !state?.has_profile_password) {
      newPassword = await ask('Set Safe Mode password', 'Choose the admin password that will protect editing.', { secure: true })
      if (newPassword === null) return
      if (!newPassword.trim()) {
        setToast({ type: 'error', message: 'A password is required to enable Safe Mode.' })
        return
      }
    }
    await perform(() => window.pywebview.api.change_profile(profile, password, newPassword), `Protection mode changed to ${profile === 'default' ? 'Admin' : 'Safe Mode'}.`)
  }

  async function setPassword() {
    let current = ''
    if (state?.has_profile_password) {
      current = await ask('Current admin password', 'Confirm your current password before changing it.', { secure: true })
      if (current === null) return
    }
    const next = await ask('Set Safe Mode password', 'Enter a new password. Leave blank to remove the password lock.', { secure: true, allowBlank: true })
    if (next === null) return
    await perform(() => window.pywebview.api.set_profile_password(current, next), 'Password settings saved.')
  }

  async function restoreAdmin() {
    let password = ''
    if (state?.has_profile_password) {
      password = await ask('Restore Admin mode', 'Enter the admin password to leave Safe Mode.', { secure: true })
      if (password === null) return
    }
    const result = await perform(() => window.pywebview.api.restore_admin(password), 'Admin mode restored.')
    if (result) setAdminPanel(false)
  }

  async function openAdminAccess() {
    let password = ''
    if (safeMode && state?.has_profile_password) {
      password = await ask('Admin access', 'Enter the admin password to open Safe Mode controls.', { secure: true })
      if (password === null) return
    }
    await perform(
      () => window.pywebview.api.admin_access(password),
      null,
      () => setAdminPanel(true),
    )
  }

  async function applyHosts() {
    await perform(
      () => window.pywebview.api.apply_hosts(),
      null,
      async (result) => {
        await refreshState()
        setToast({ type: result.flushed ? 'success' : 'error', message: result.flushed ? 'Hosts protection applied and DNS cache flushed.' : `Hosts protection applied, but DNS cache flush failed: ${result.error}` })
      },
    )
  }

  async function removeHosts() {
    const confirmed = await ask('Remove Avantis hosts rules?', 'Only the Avantis-managed section will be removed from the Windows hosts file.', { confirm: true, confirmLabel: 'Remove rules' })
    if (!confirmed) return
    await perform(
      () => window.pywebview.api.remove_hosts(),
      null,
      async (result) => {
        await refreshState()
        setToast({ type: result.flushed ? 'success' : 'error', message: result.removed ? (result.flushed ? 'Avantis hosts rules removed.' : `Rules removed; DNS flush failed: ${result.error}`) : 'No Avantis hosts rules were found.' })
      },
    )
  }

  async function exportFeed() {
    await perform(
      () => window.pywebview.api.export_dns_feed(),
      null,
      (result) => setToast({ type: result.cancelled ? 'info' : 'success', message: result.cancelled ? 'Export cancelled.' : `${result.count} domains exported.` }),
    )
  }

  async function changeRetention(hours) {
    await perform(() => window.pywebview.api.update_retention(hours), 'Activity retention updated.')
  }

  async function clearActivity() {
    const confirmed = await ask('Clear activity history?', 'This permanently removes the locally stored manual check records.', { confirm: true, confirmLabel: 'Clear activity' })
    if (confirmed) await perform(() => window.pywebview.api.clear_activity(), 'Activity history cleared.')
  }

  async function loadDictionary() {
    const result = await window.pywebview.api.get_dictionary()
    setDictionary(result)
  }

  async function addRule() {
    const password = await writePassword('edit rules in Safe Mode')
    if (password === null) return
    await perform(
      () => window.pywebview.api.add_rule(newCategory, newKeyword, password),
      'Detection rule saved.',
      async (next) => {
        setState(next)
        setNewKeyword('')
      },
    )
  }

  async function removeRules() {
    if (!selectedRules.length) return
    const password = await writePassword('edit rules in Safe Mode')
    if (password === null) return
    const rules = selectedRules.map(([category, keyword]) => ({ category, keyword }))
    await perform(
      () => window.pywebview.api.remove_rules(rules, password),
      `${rules.length} rule${rules.length === 1 ? '' : 's'} removed.`,
      async (next) => {
        setState(next)
        setSelectedRules([])
      },
    )
  }

  useEffect(() => {
    if (apiReady && page === 'insights' && insightTab === 'dictionary') loadDictionary().catch(showError)
  }, [apiReady, page, insightTab, state?.blocked_domains?.length, state?.categories])

  if (!apiReady || !state) {
    return (
      <main className="loading-screen">
        <div className="loading-mark"><Shield size={25} /></div>
        <p>{!apiReady && bridgeTimedOut ? 'The desktop bridge is not responding. Close this window and relaunch Avantis from PowerShell.' : startupError ? 'Avantis could not load local settings.' : apiReady ? 'Loading local protection settings…' : 'Waiting for the Avantis desktop bridge…'}</p>
        {startupError && <><pre className="startup-error">{startupError}</pre><button className="button button-outline" onClick={() => refreshState().catch(showError)}>Retry connection</button></>}
      </main>
    )
  }

  const visibleRules = Object.entries(state.categories || {}).flatMap(([category, keywords]) =>
    keywords.map((keyword) => [category, keyword]),
  ).filter(([category, keyword]) => !ruleQuery || `${category} ${keyword}`.toLowerCase().includes(ruleQuery.toLowerCase()))

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img className="brand-logo" src={logo} alt="Avantis, Product of Zimbabwe" />
          <span className="brand-product">FIREWALL</span>
        </div>
        <nav className="primary-nav" aria-label="Main navigation">
          {hiddenPages.map(({ id, label }) => (
            <button key={id} className={`nav-link ${page === id ? 'active' : ''}`} onClick={() => setPage(id)}>
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className={`mode-chip ${safeMode ? 'safe' : ''}`}>
            <div><strong>{safeMode ? 'Safe Mode' : 'Admin mode'}</strong></div>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><strong>{pages.find((item) => item.id === page)?.label}</strong></div>
          <div className="top-actions">
            <span className={`connection ${hostsActive ? 'active' : hostsStatusLevel === 'error' ? 'error' : 'idle'}`}>{hostsStatusLabel}</span>
            {safeMode ? (
              <button className="button button-quiet" onClick={openAdminAccess}><KeyRound size={15} /> Admin access</button>
            ) : (
              <button className="button button-quiet" onClick={setPassword}><LockKeyhole size={15} /> Safe Mode password</button>
            )}
          </div>
        </header>

        <div className="page-content">
          {page === 'protect' && (
            <>
              <div className="page-heading">
                <div><h1>Protection</h1><p>Check a site or review your block list.</p></div>
                <div className={`profile-select ${safeMode ? 'safe' : ''}`}>
                  <div><strong>{safeMode ? 'Safe Mode' : 'Admin'}</strong></div>
                  <select aria-label="Protection profile" value={state.protection_profile} onChange={(event) => changeProfile(event.target.value)}>
                    <option value="default">Admin</option><option value="child_protection">Safe Mode</option>
                  </select>
                </div>
              </div>

              <section className="stats-row" aria-label="Protection statistics">
                <Stat label="Blocked domains" value={state.blocked_domains.length} />
                <Stat label="Detection rules" value={Object.values(state.categories).reduce((sum, words) => sum + words.length, 0)} />
                <Stat label="Manual checks" value={state.activity.events.length} />
              </section>

              <div className="protect-grid">
                <section className="surface analysis-panel">
                  <div className="section-heading"><div><h2>Check a website</h2></div></div>
                  <p className="section-copy">Check a site against your block list and device rules.</p>
                  <form className="analyze-form" onSubmit={(event) => { event.preventDefault(); analyze() }}>
                    <div className="input-wrap"><Search size={17} /><input value={analysisInput} onChange={(event) => setAnalysisInput(event.target.value)} placeholder="example.com or https://example.com" aria-label="Website or domain" /></div>
                    <button className="button button-primary" disabled={busy}>Check site</button>
                  </form>
                  {analysis ? <AnalysisResult result={analysis} /> : <div className="signal-note"><span>Checks run on this device. No domain lookup is sent to Avantis.</span></div>}
                </section>

                {!safeMode && <section className="surface quick-add">
                  <div className="section-heading"><div><h2>Block a domain</h2></div></div>
                  <p className="section-copy">It will be blocked in Windows after you select Apply to Hosts.</p>
                  <form className="stack-form" onSubmit={(event) => { event.preventDefault(); addDomains(addInput, () => setAddInput('')) }}>
                    <input value={addInput} onChange={(event) => setAddInput(event.target.value)} placeholder="domain.com" aria-label="Domain to block" />
                    <button className="button button-primary" disabled={busy}><Plus size={16} /> Add domain</button>
                  </form>
                  <div className="micro-note">System domains are excluded automatically.</div>
                </section>}
              </div>

              {!safeMode && <section className="surface hosts-panel">
                <div className="section-heading hosts-heading"><div><h2>Block sites on this PC</h2></div><StatusPill status={state.hosts_status} /></div>
                <div className="hosts-controls">
                  <div className="hosts-explainer"><strong>Windows block list</strong><span>Only Avantis entries are changed. Administrator permission is required.</span></div>
                  <div className="button-row">
                    <button className="button button-outline" onClick={() => refreshState().then(() => setToast({ type: 'success', message: 'Hosts file status refreshed.' })).catch(showError)} disabled={busy}><Activity size={15} /> Check status</button>
                    <button className="button button-primary" onClick={applyHosts} disabled={busy}><ShieldCheck size={16} /> Apply to Hosts</button>
                    <button className="button button-outline" onClick={removeHosts} disabled={busy}><Trash2 size={15} /> Remove rules</button>
                    <button className="button button-outline" onClick={exportFeed} disabled={busy}><ArrowDownToLine size={15} /> Export DNS feed</button>
                  </div>
                </div>
              </section>}
              {safeMode && <section className="safe-banner"><div><strong>Safe Mode is active</strong><span>An admin must unlock this profile to edit settings or change Windows protection.</span></div><button onClick={openAdminAccess}>Admin access</button></section>}
            </>
          )}

          {page === 'import' && <>
            <PageTitle eyebrow="BULK MANAGEMENT" title="Import domains" description="Bring a list into your local rules. Existing domains and protected system domains are skipped." />
            <section className="surface import-surface">
              <div className="section-heading"><div><h2>Bulk import</h2></div></div>
              <p className="section-copy">Separate domains with new lines, commas, semicolons, or spaces.</p>
              <textarea value={bulkInput} onChange={(event) => setBulkInput(event.target.value)} placeholder={'example.com\nsubdomain.example.net'} aria-label="Domains to import" />
              <div className="import-footer"><span>{bulkInput.trim() ? bulkInput.trim().split(/[\s,;]+/).filter(Boolean).length : 0} entries detected</span><div className="button-row"><button className="button button-outline" onClick={importFile} disabled={busy}><Upload size={15} /> Import file</button><button className="button button-primary" disabled={busy || !bulkInput.trim()} onClick={() => addDomains(bulkInput, () => setBulkInput(''))}><Plus size={16} /> Add all</button></div></div>
              <div className="signal-note"><CircleHelp size={16} /><span>Supported files: TXT, CSV, JSON, and DOCX. Imported entries are saved locally; hosts rules change only after an explicit Apply.</span></div>
            </section>
          </>}

          {page === 'domains' && <>
            <PageTitle eyebrow="LOCAL RULE LIST" title="Blocked domains" description="Manage domains saved on this device. Applying changes to Windows is a separate action." />
            <section className="surface domain-surface">
              <div className="list-toolbar"><div className="domain-count"><strong>{state.blocked_domains.length}</strong><span>domains</span></div><div className="list-actions"><div className="search-control"><Search size={16} /><input value={domainQuery} onChange={(event) => setDomainQuery(event.target.value)} placeholder="Filter domains" aria-label="Filter blocked domains" /></div><button className="button button-outline" onClick={removeSelected} disabled={busy || !selectedDomains.length}><Trash2 size={15} /> Remove selected{selectedDomains.length ? ` (${selectedDomains.length})` : ''}</button><button className="icon-button danger" onClick={clearDomains} title="Clear all blocked domains" aria-label="Clear all blocked domains" disabled={busy || !state.blocked_domains.length}><Trash2 size={16} /></button></div></div>
              <div className="domain-table-wrap"><table className="domain-table"><thead><tr><th><input type="checkbox" aria-label="Select all filtered domains" checked={shownDomains.length > 0 && shownDomains.every((domain) => selectedDomains.includes(domain))} onChange={(event) => setSelectedDomains(event.target.checked ? [...new Set([...selectedDomains, ...shownDomains])] : selectedDomains.filter((domain) => !shownDomains.includes(domain)))} /></th><th>DOMAIN</th><th>RULE</th><th>STATUS</th></tr></thead><tbody>
                {shownDomains.map((domain) => <tr key={domain}><td><input type="checkbox" aria-label={`Select ${domain}`} checked={selectedDomains.includes(domain)} onChange={(event) => setSelectedDomains((current) => event.target.checked ? [...current, domain] : current.filter((item) => item !== domain))} /></td><td className="domain-name"><Globe2 size={15} />{domain}</td><td><span className="rule-label">Domain + subdomains</span></td><td><span className="table-status"><i /> Saved locally</span></td></tr>)}
                {!shownDomains.length && <tr><td colSpan="4" className="empty-row">{domainQuery ? 'No domains match your filter.' : 'Your block list is empty.'}</td></tr>}
              </tbody></table></div>
              <div className="table-foot"><span>Showing {shownDomains.length} of {state.blocked_domains.length}</span><span>Rules are not applied until you select Apply to Hosts.</span></div>
            </section>
          </>}

          {page === 'insights' && <>
            <PageTitle eyebrow="LOCAL ACTIVITY & CONFIGURATION" title="Insights & rules" description="Review manual checks, search your current dictionary, and refine detection rules." />
            <div className="insight-tabs" role="tablist">
              {[['activity', 'Activity', Activity], ['dictionary', 'Dictionary', Search], ['rules', 'Rule library', ListFilter]].map(([id, label, Icon]) => <button key={id} className={insightTab === id ? 'selected' : ''} role="tab" aria-selected={insightTab === id} onClick={() => setInsightTab(id)}><Icon size={15} />{label}</button>)}
            </div>
            {insightTab === 'activity' && <section className="surface insights-surface">
              <div className="list-toolbar"><div><h2>Activity</h2></div><label className="retention-select"><span>Keep for</span><select value={state.activity.retention_hours} onChange={(event) => changeRetention(Number(event.target.value))}>{retentionOptions.map((option) => <option key={option.hours} value={option.hours}>{option.label}</option>)}</select></label></div>
              <p className="section-copy">Successful browsing is not logged. Records stay in the local activity file and expire automatically.</p>
              <div className="activity-list">{[...state.activity.events].reverse().map((event, index) => <div className="activity-item" key={`${event.timestamp}-${index}`}><div className="activity-icon"><Search size={15} /></div><div className="activity-main"><strong>{event.domain}</strong><span>{event.detail}</span></div><time>{new Date(event.timestamp).toLocaleString()}</time></div>)}{!state.activity.events.length && <div className="empty-state"><Activity size={22} /><strong>No manual checks yet</strong><span>Results from Analyze a website will appear here.</span></div>}</div>
              <div className="table-foot"><span>{state.activity.events.length} record{state.activity.events.length === 1 ? '' : 's'} stored locally</span><button className="text-button danger-text" onClick={clearActivity} disabled={!state.activity.events.length}><Trash2 size={14} /> Clear activity</button></div>
            </section>}
            {insightTab === 'dictionary' && <section className="surface insights-surface">
              <div className="list-toolbar"><div><h2>Dictionary</h2></div><div className="search-control"><Search size={16} /><input value={dictionaryQuery} onChange={(event) => setDictionaryQuery(event.target.value)} placeholder="Search entries" aria-label="Search dictionary" /></div></div>
              <div className="dictionary-table-wrap"><table className="domain-table dictionary-table"><thead><tr><th>TYPE</th><th>DOMAIN OR WORD</th><th>CATEGORY</th><th>MEANING</th></tr></thead><tbody>{dictionary.filter((entry) => Object.values(entry).some((value) => String(value).toLowerCase().includes(dictionaryQuery.toLowerCase()))).map((entry, index) => <tr key={`${entry.type}-${entry.entry}-${index}`}><td><span className={`type-tag ${entry.type.toLowerCase()}`}>{entry.type}</span></td><td className="domain-name">{entry.entry}</td><td>{entry.category}</td><td className="meaning-cell">{entry.meaning}</td></tr>)}{!dictionary.length && <tr><td colSpan="4" className="empty-row">No dictionary entries.</td></tr>}</tbody></table></div>
              <div className="table-foot"><span>{dictionary.filter((entry) => Object.values(entry).some((value) => String(value).toLowerCase().includes(dictionaryQuery.toLowerCase()))).length} entries shown</span><span>Reference only; edit terms in Rule library.</span></div>
            </section>}
            {insightTab === 'rules' && <section className="surface insights-surface">
              <div className="list-toolbar"><div><h2>Rules</h2></div><div className="search-control"><Search size={16} /><input value={ruleQuery} onChange={(event) => setRuleQuery(event.target.value)} placeholder="Filter rules" aria-label="Filter rules" /></div></div>
              <div className="rule-list">{visibleRules.map(([category, keyword]) => { const key = `${category}\u0000${keyword}`; return <label key={key} className="rule-row"><input type="checkbox" checked={selectedRules.some(([itemCategory, itemKeyword]) => itemCategory === category && itemKeyword === keyword)} onChange={(event) => setSelectedRules((current) => event.target.checked ? [...current, [category, keyword]] : current.filter(([itemCategory, itemKeyword]) => itemCategory !== category || itemKeyword !== keyword))} /><span className={`category-dot ${category}`} /><strong>{keyword}</strong><span className="rule-category">{category}</span></label> })}{!visibleRules.length && <div className="empty-row">No rules match this filter.</div>}</div>
              <div className="rule-editor"><label>Category<input value={newCategory} onChange={(event) => setNewCategory(event.target.value)} placeholder="e.g. gambling" /></label><label>Keyword or phrase<input value={newKeyword} onChange={(event) => setNewKeyword(event.target.value)} placeholder="e.g. betting" onKeyDown={(event) => event.key === 'Enter' && addRule()} /></label><button className="button button-primary" onClick={addRule} disabled={busy || !newCategory.trim() || !newKeyword.trim()}><Plus size={15} /> Add rule</button></div>
              <div className="table-foot"><span>{visibleRules.length} rules shown</span><button className="text-button danger-text" onClick={removeRules} disabled={busy || !selectedRules.length}><Trash2 size={14} /> Remove selected{selectedRules.length ? ` (${selectedRules.length})` : ''}</button></div>
            </section>}
          </>}
        </div>
      </main>

      {toast && <div className={`toast ${toast.type}`} role="status"><span className="toast-mark">{toast.type === 'success' ? <Check size={16} /> : toast.type === 'error' ? <AlertTriangle size={16} /> : <CircleHelp size={16} />}</span><span>{toast.message}</span><button onClick={() => setToast(null)} aria-label="Dismiss notification"><X size={15} /></button></div>}
      {adminPanel && <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && setAdminPanel(false)}><section className="admin-panel"><div className="admin-panel-heading"><div className="modal-icon"><LockKeyhole size={19} /></div><button className="icon-button" onClick={() => setAdminPanel(false)} aria-label="Close admin access"><X size={16} /></button></div><h2>Admin access</h2><p>Review Safe Mode and manage the access controls for this device.</p><div className="admin-stats"><div><small>PROFILE</small><strong>Safe Mode</strong></div><div><small>PASSWORD</small><strong>{state.has_profile_password ? 'Enabled' : 'Disabled'}</strong></div><div><small>BLOCKED</small><strong>{state.blocked_domains.length}</strong></div></div><div className="admin-actions"><button className="button button-outline" onClick={setPassword}><KeyRound size={15} /> Set / change password</button><button className="button button-primary" onClick={restoreAdmin}><ShieldCheck size={15} /> Restore Admin</button></div><div className="admin-note">Only the admin password can turn off Safe Mode and restore Admin mode.</div></section></div>}
      {modal && <Modal modal={modal} onClose={closeModal} />}
    </div>
  )
}

function Stat({ label, value }) {
  return <div className="stat-item"><div className="stat-copy"><span>{label}</span><strong>{value}</strong></div></div>
}

function PageTitle({ title, description }) {
  return <div className="page-heading simple"><div><h1>{title}</h1><p>{description}</p></div></div>
}

function StatusPill({ status }) {
  const [message, level] = status || ['Hosts status unavailable.', 'warning']
  const active = /\d+ Avantis hostnames in \d+ mappings\./.test(message)
  const idle = message.includes('No Avantis-managed rules found')
  const statusClass = level === 'error' ? 'error' : active ? 'active' : idle ? 'idle' : 'warning'
  const label = active ? 'Rules active' : idle ? 'Not applied' : 'Check needed'
  return <span className={`status-pill ${statusClass}`}>{label}</span>
}

function AnalysisResult({ result }) {
  const riskClass = result.level === 'High risk' ? 'high' : result.level === 'Review' ? 'review' : 'low'
  const reasons = []
  if (result.dns_feed_blocked) reasons.push('Listed in the Avantis DNS blocklist feed')
  else if (result.blocked) reasons.push('Already blocked or a subdomain of a blocked site')
  if (result.categories?.length) reasons.push(`Categories: ${result.categories.join(', ')}`)
  if (result.keywords?.length) reasons.push(`Matched words: ${result.keywords.join(', ')}`)
  if (result.signals?.length) reasons.push(...result.signals)
  return <div className={`analysis-result ${riskClass}`}>
    <div className="result-top"><div className="result-domain"><span className="result-icon">{riskClass === 'high' ? <ShieldAlert size={18} /> : riskClass === 'review' ? <AlertTriangle size={18} /> : <ShieldCheck size={18} />}</span><div><strong>{result.domain || 'Unrecognized domain'}</strong></div></div><div className="risk-score"><strong>{result.score}</strong><span>/ 100</span></div></div>
    <div className="score-track"><i style={{ width: `${result.score}%` }} /></div>
    <div className="result-summary"><strong>{result.level}</strong><span>{result.recommendation}</span></div>
    {reasons.length > 0 && <ul className="reason-list">{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
  </div>
}

function Modal({ modal, onClose }) {
  const [value, setValue] = useState('')
  const inputRef = useRef(null)
  useEffect(() => { if (!modal.confirm) inputRef.current?.focus() }, [modal])
  function submit(event) {
    event.preventDefault()
    onClose(modal.confirm ? true : value)
  }
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose(modal.confirm ? false : null)}>
    <form className="modal" onSubmit={submit}>
      <div className="modal-icon">{modal.confirm ? <AlertTriangle size={19} /> : modal.secure ? <KeyRound size={19} /> : <CircleHelp size={19} />}</div>
      <h2>{modal.title}</h2><p>{modal.description}</p>
      {!modal.confirm && <input ref={inputRef} type={modal.secure ? 'password' : 'text'} value={value} onChange={(event) => setValue(event.target.value)} autoComplete="off" aria-label={modal.title} />}
      <div className="modal-actions"><button type="button" className="button button-outline" onClick={() => onClose(modal.confirm ? false : null)}>Cancel</button><button className={`button ${modal.confirm ? 'button-danger' : 'button-primary'}`}>{modal.confirm ? (modal.confirmLabel || 'Continue') : 'Continue'}</button></div>
    </form>
  </div>
}

export default App