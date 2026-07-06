<script lang="ts">
  // Throwaway visual mockup for the "blend" direction (dark shell + calm layout).
  // Not wired into the app; used only to preview the redesign.
  const tabs = ['Home', 'Analyze', 'Backup', 'Report', 'History'];
  const findings = [
    {
      sev: 'high', tag: 'GAP', icon: 'M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
      title: 'Management plane reachable from WAN',
      meta: 'Segmentation · SEG-MGMT-WAN · quick fix',
      body: "Your gateway's admin interface accepts connections from the internet.",
      rec: 'Restrict management access to the LAN or a VPN.',
    },
    {
      sev: 'warn', tag: 'RECOMMENDATION', icon: 'M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
      title: 'No geo-IP blocking on inbound WAN',
      meta: 'Firewall · FW-GEO-IN · quick fix',
      body: 'No policy blocks inbound traffic from high-risk regions.',
      rec: 'Block inbound from CN, RU, KP, IR.',
    },
    {
      sev: 'info', tag: 'RECOMMENDATION', icon: 'M12 16v-4m0-4h.01M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0z',
      title: 'Controller version 10.4.57 is outside the tested range',
      meta: 'Audit scope · API-VERSION · quick fix',
      body: 'Network 10.4.57 is newer than the latest version this tool was verified against.',
      rec: 'Confirm the results and check for a tool update.',
    },
  ];
  const sevColor: Record<string, string> = {
    high: '#f2555a', warn: '#e0a13a', info: '#5b9bf6', ok: '#34d399',
  };
  const sevTint: Record<string, string> = {
    high: '#241417', warn: '#241d10', info: '#131f38', ok: '#10251d',
  };
</script>

<div style="min-height:100vh; background:#0e1116; color:#e6eaf0; font-family:system-ui,-apple-system,'Segoe UI',sans-serif;">
  <nav style="display:flex; align-items:center; gap:2px; padding:0 20px; border-bottom:1px solid #1c222b; background:#0e1116; position:sticky; top:0;">
    <span style="font-weight:600; font-size:14px; margin-right:20px; color:#e6eaf0; display:flex; align-items:center; gap:8px;">
      <span style="width:8px; height:8px; border-radius:50%; background:#3b82f6;"></span>UniFi Security Advisor
    </span>
    {#each tabs as t}
      <a href="#" style="padding:14px 14px; font-size:13px; font-weight:500; text-decoration:none;
        color:{t === 'Report' ? '#e6eaf0' : '#7d8796'};
        border-bottom:2px solid {t === 'Report' ? '#3b82f6' : 'transparent'};">{t}</a>
    {/each}
  </nav>

  <main style="max-width:760px; margin:0 auto; padding:28px 24px 60px;">
    <a href="#" style="color:#7d8796; font-size:13px; text-decoration:none;">← Home</a>

    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin:14px 0 20px;">
      <div>
        <h1 style="font-size:24px; font-weight:600; margin:0;">Security report</h1>
        <p style="color:#9aa5b4; font-size:14px; margin:6px 0 0;">Cloud Gateway Fiber · Network 10.4.57</p>
      </div>
      <div style="text-align:right;">
        <div style="display:flex; align-items:baseline; gap:8px; justify-content:flex-end;">
          <span style="font-size:34px; font-weight:600; line-height:1;">87</span>
          <span style="font-size:14px; font-weight:600; color:#34d399; background:#10251d; padding:3px 10px; border-radius:999px;">B+</span>
        </div>
        <div style="font-size:12px; color:#6b7684; margin-top:6px;">4 issues · 6 unknown · 1 good</div>
      </div>
    </div>

    <div style="display:flex; height:6px; border-radius:999px; overflow:hidden; margin-bottom:24px; background:#1c222b;">
      <div style="width:36%; background:#f2555a;"></div>
      <div style="width:20%; background:#e0a13a;"></div>
      <div style="width:9%; background:#34d399;"></div>
    </div>

    <div style="display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap;">
      {#each [['Issues', 4, true], ['Unknown', 6, false], ['Good', 1, false], ['All', 11, false]] as [label, n, active]}
        <button style="font-size:13px; font-weight:500; padding:6px 14px; border-radius:999px; cursor:pointer;
          border:1px solid {active ? '#3b82f6' : '#232a34'};
          background:{active ? '#16233b' : 'transparent'};
          color:{active ? '#8fb8ff' : '#9aa5b4'};">{label} ({n})</button>
      {/each}
    </div>

    <div style="display:flex; flex-direction:column; gap:12px;">
      {#each findings as f}
        <div style="background:#161b22; border:1px solid #232a34; border-radius:12px; padding:16px 18px; display:flex; gap:14px;">
          <div style="width:36px; height:36px; border-radius:10px; flex:none; display:flex; align-items:center; justify-content:center; background:{sevTint[f.sev]};">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={sevColor[f.sev]} stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d={f.icon}/></svg>
          </div>
          <div style="flex:1;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
              <h3 style="font-size:15px; font-weight:600; margin:0;">{f.title}</h3>
              <span style="font-size:10px; font-weight:600; letter-spacing:0.04em; color:{sevColor[f.sev]}; flex:none; margin-top:2px;">{f.tag}</span>
            </div>
            <p style="font-size:12px; color:#6b7684; margin:4px 0 0;">{f.meta}</p>
            <p style="font-size:14px; color:#c3ccd8; margin:10px 0 0; line-height:1.55;">{f.body}</p>
            <a href="#" style="display:inline-flex; align-items:center; gap:6px; font-size:13px; color:#5b9bf6; text-decoration:none; margin-top:10px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
              {f.rec}
            </a>
          </div>
        </div>
      {/each}
    </div>
  </main>
</div>
