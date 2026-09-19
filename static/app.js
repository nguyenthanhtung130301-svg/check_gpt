(() => {
  'use strict';

  const state = { token: '', jobs: new Map(), filter: 'all', settings: {}, events: null, output: '', draftTimer: null, pendingLaunch: null, activeMode: 'check_only', selectedJob: null };
  const $ = (id) => document.getElementById(id);
  const statusLabels = { queued: 'ĐANG CHỜ', running: 'ĐANG CHẠY', success: 'THÀNH CÔNG', error: 'LỖI', cancelled: 'ĐÃ DỪNG' };
  const errorLabels = {
    account_die: 'TÀI KHOẢN DIE',
    invalid_credentials: 'SAI MẬT KHẨU / 2FA',
    technical_error: 'LỖI KỸ THUẬT',
  };
  const MODE_LABELS = {
    check_only: { short: 'CHỈ KIỂM TRA', title: 'Kiểm tra tài khoản', icon: '✓', description: 'Xác định trạng thái Live, Free hoặc Plus mà không thay đổi thông tin.' },
    change_2fa: { short: 'ĐỔI 2FA', title: 'Cập nhật 2FA', icon: '⟳', description: 'Tạo khóa TOTP mới, sau đó đăng nhập lại để kiểm tra.' },
    change_password: { short: 'ĐỔI MẬT KHẨU', title: 'Cập nhật mật khẩu', icon: '🔑', description: 'Tạo mật khẩu mới, giữ nguyên 2FA và xác minh phiên đăng nhập.' },
    change_password_and_2fa: { short: 'MẬT KHẨU + 2FA', title: 'Cập nhật toàn bộ', icon: '⬡', description: 'Thay mật khẩu và khóa TOTP trong cùng một quy trình xác minh.' },
  };

  function planLabel(job) {
    return job.plan ? String(job.plan).toUpperCase() : 'CHƯA RÕ';
  }

  function planExpiryLabel(job) {
    const plan = String(job.plan || '').toLowerCase();
    if (!plan || plan === 'free' || !job.plan_expires_at) return '';

    let raw = job.plan_expires_at;
    if (/^\d+(?:\.\d+)?$/.test(String(raw))) {
      raw = Number(raw);
      if (raw < 1e12) raw *= 1000;
    }
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) return '';

    const formatted = new Intl.DateTimeFormat('vi-VN', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      timeZone: 'Asia/Ho_Chi_Minh',
    }).format(date);
    return `HẾT HẠN / GIA HẠN · ${formatted}`;
  }

  function statusLabel(job) {
    if (isVerifyFailure(job)) return 'VERIFY THẤT BẠI · 2FA ĐÃ ĐỔI';
    if (job.status === 'success') return `THÀNH CÔNG · ${planLabel(job)}`;
    if (job.status === 'error' && job.error_kind) return errorLabels[job.error_kind] || 'LỖI';
    return statusLabels[job.status] || job.status;
  }

  function isVerifyFailure(job) {
    return Boolean(job.verify_failed || (
      job.status === 'error' && job.rotated_pending_verify && !job.login_verified
    ));
  }

  function accountCheck(job) {
    if (isVerifyFailure(job)) return { label: '2FA ĐÃ ĐỔI', className: 'verify-failed', detail: job.error || 'Đăng nhập verify bằng 2FA mới thất bại' };
    if (job.account_state === 'die') return { label: 'DIE', className: 'die', detail: job.error || 'Tài khoản đã bị vô hiệu hóa' };
    if (job.account_state === 'live') return { label: `LIVE · ${planLabel(job)}`, className: 'live', detail: `Gói kiểm tra từ ${job.plan_source || 'session'}` };
    if (job.error_kind === 'invalid_credentials') return { label: 'CHƯA XÁC MINH', className: 'unknown', detail: job.error || 'Thông tin đăng nhập hoặc 2FA không đúng' };
    return { label: 'CHƯA RÕ', className: 'unknown', detail: job.error || 'Chưa kiểm tra xong tài khoản' };
  }

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}), 'X-Auth-Token': state.token };
    if (options.body) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, { ...options, headers });
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).detail || message; } catch (_) { /* plain error */ }
      throw new Error(message);
    }
    return response.headers.get('content-type')?.includes('json') ? response.json() : response.text();
  }

  function toast(message, type = '') {
    const node = document.createElement('div');
    node.className = `toast ${type}`;
    node.textContent = message;
    $('toast-stack').appendChild(node);
    setTimeout(() => node.remove(), 3800);
  }

  function updateEditor() {
    const value = $('combo-input').value;
    const count = value.trim() ? value.split(/\r?\n/).filter(Boolean).length : 0;
    $('line-count').textContent = `${count} dòng`;
    $('line-numbers').textContent = Array.from({ length: Math.max(1, value.split(/\r?\n/).length) }, (_, i) => i + 1).join('\n');
    document.querySelector('.cursor-hint').style.display = value ? 'none' : 'block';
  }

  function modeValue() {
    return state.activeMode;
  }

  function proxyPool() {
    return Array.isArray(state.settings['twofa.proxy_pool'])
      ? state.settings['twofa.proxy_pool']
      : [];
  }

  function proxyInputLines() {
    return $('setting-proxy-pool').value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  }

  function updateProxySummary() {
    const savedCount = proxyPool().length;
    const inputCount = proxyInputLines().length;
    $('proxy-summary').textContent = savedCount ? `${savedCount} PROXY` : 'DIRECT';
    $('setting-proxy-count').textContent = `${inputCount} proxy`;
  }

  function resetProxyTest() {
    $('proxy-test-summary').textContent = 'Chưa kiểm tra';
    $('proxy-test-results').hidden = true;
    $('proxy-test-results').replaceChildren();
  }

  async function testProxies() {
    const proxies = proxyInputLines();
    if (!proxies.length) return toast('Hãy nhập ít nhất một proxy để kiểm tra.', 'error');
    const button = $('test-proxies');
    const label = $('test-proxies-label');
    button.disabled = true;
    button.classList.add('is-testing');
    button.setAttribute('aria-busy', 'true');
    label.textContent = `Đang kiểm tra ${proxies.length} proxy`;
    $('proxy-test-summary').textContent = 'Đang lấy IP proxy…';
    $('proxy-test-results').hidden = true;
    try {
      const data = await api('/api/proxies/test', {
        method: 'POST',
        body: JSON.stringify({ proxies }),
      });
      $('proxy-test-results').innerHTML = data.results.map((result) => {
        const meta = (result.ok
          ? [`IP ${result.exit_ip}`, result.country, result.latency_ms != null ? `${result.latency_ms} ms` : '', result.checked_at]
          : [result.detail, result.latency_ms != null ? `${result.latency_ms} ms` : '', result.checked_at])
          .filter(Boolean).join(' · ');
        return `<div class="proxy-test-row is-${escapeHtml(result.kind)}">
          <span class="proxy-test-index">#${String(result.index).padStart(2, '0')}</span>
          <span class="proxy-test-info"><strong>${escapeHtml(result.label)}</strong><small>${escapeHtml(meta || result.detail)}</small></span>
          <span class="proxy-test-state">${result.ok ? 'OK' : escapeHtml(result.status ? `HTTP ${result.status}` : 'LỖI')}</span>
        </div>`;
      }).join('');
      $('proxy-test-results').hidden = false;
      $('proxy-test-summary').textContent = `${data.ok}/${data.results.length} proxy dùng được`;
      toast(data.failed ? `Có ${data.failed} proxy không lấy được IP.` : 'Tất cả proxy đã trả IP hiện tại.', data.failed ? 'error' : '');
    } catch (error) {
      $('proxy-test-summary').textContent = 'Kiểm tra thất bại';
      toast(`Không test được proxy: ${error.message}`, 'error');
    } finally {
      button.disabled = false;
      button.classList.remove('is-testing');
      button.removeAttribute('aria-busy');
      label.textContent = 'Kiểm tra proxy';
    }
  }

  function renderMode() {
    document.querySelectorAll('.mode-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.mode === state.activeMode);
    });
  }

  function scheduleDraftSave() {
    updateEditor();
    clearTimeout(state.draftTimer);
    state.draftTimer = setTimeout(async () => {
      state.settings['twofa.input_draft'] = $('combo-input').value;
      try {
        const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(settingsPayload()) });
        state.settings = data.settings;
      } catch (error) {
        toast(`Không lưu được danh sách nháp: ${error.message}`, 'error');
      }
    }, 450);
  }

  function counts() {
    const jobs = [...state.jobs.values()];
    const running = jobs.filter((job) => ['queued', 'running'].includes(job.status)).length;
    const success = jobs.filter((job) => job.status === 'success').length;
    const error = jobs.filter((job) => ['error', 'cancelled'].includes(job.status)).length;
    const verifyFailed = jobs.filter(isVerifyFailure).length;
    const retryableErrors = jobs.filter((job) => ['error', 'cancelled'].includes(job.status) && job.retryable !== false).length;
    $('metric-running').textContent = running;
    $('metric-success').textContent = success;
    $('metric-errors').textContent = error;
    $('count-all').textContent = jobs.length;
    $('count-running').textContent = running;
    $('count-success').textContent = success;
    $('count-error').textContent = error;
    $('count-verify-failed').textContent = verifyFailed;
    $('copy-failed-count').textContent = error;
    $('copy-failed').disabled = error === 0;
    $('retry-failed-count').textContent = retryableErrors;
    $('retry-failed').disabled = retryableErrors === 0;
  }

  function filteredJobs() {
    const jobs = [...state.jobs.values()].sort((a, b) => a.created_at - b.created_at);
    if (state.filter === 'running') return jobs.filter((j) => ['queued', 'running'].includes(j.status));
    if (state.filter === 'error') return jobs.filter((j) => ['error', 'cancelled'].includes(j.status));
    if (state.filter === 'verify_failed') return jobs.filter(isVerifyFailure);
    if (state.filter === 'success') return jobs.filter((j) => j.status === 'success');
    return jobs;
  }

  function render() {
    counts();
    const jobs = filteredJobs();
    $('empty-state').style.display = jobs.length ? 'none' : 'grid';
    $('job-list').innerHTML = jobs.map((job) => {
      const check = accountCheck(job);
      const planExpiry = planExpiryLabel(job);
      const modeShort = (MODE_LABELS[job.mode] || { short: job.mode.toUpperCase() }).short;
      const verifyFailed = isVerifyFailure(job);
      const checkpoint = job.mode === 'check_only' && job.status === 'success'
        ? 'ĐÃ CHECK LIVE · KHÔNG ĐỔI'
        : job.login_verified
          ? 'ĐÃ XÁC MINH THÀNH CÔNG'
          : verifyFailed
            ? '2FA MỚI ĐÃ LƯU · VERIFY THẤT BẠI'
            : job.rotated_pending_verify
              ? '2FA MỚI ĐÃ LƯU · ĐANG CHỜ VERIFY'
            : check.detail;
      const canRetry = ['error', 'cancelled'].includes(job.status) && job.retryable !== false;
      const canStop = ['queued', 'running'].includes(job.status);
      const selected = state.selectedJob === job.id ? ' selected' : '';
      return `<tr data-id="${job.id}" class="job-row${verifyFailed ? ' verify-failed-row' : ''}${selected}" title="${escapeHtml(job.error || '')}">
        <td class="account"><strong>${escapeHtml(job.email)}</strong><span>${job.id.slice(0, 10).toUpperCase()} · <b class="job-mode mode-${job.mode}">${escapeHtml(modeShort)}</b></span>${job.has_proxy ? `<small class="proxy-assignment">PROXY #${job.proxy_slot} · ${escapeHtml(job.proxy_label)}</small>` : ''}</td>
        <td><span class="status ${job.status}${verifyFailed ? ' verify-failed' : ''} ${job.plan ? `plan-${escapeHtml(job.plan)}` : ''}">${escapeHtml(statusLabel(job))}</span></td>
        <td><div class="account-result"><span class="account-badge ${check.className} ${job.plan ? `plan-${escapeHtml(job.plan)}` : ''}">${escapeHtml(check.label)}</span>${planExpiry ? `<small class="plan-expiry">${escapeHtml(planExpiry)}</small>` : ''}<small>${escapeHtml(checkpoint)}</small></div></td>
        <td>${job.retry_count}</td>
        <td><div class="row-actions">
          <button class="action-btn log-btn" data-action="logs">Nhật ký</button>
          ${canRetry ? '<button class="action-btn retry-btn" data-action="retry">↻ Retry</button>' : ''}
          ${canStop ? '<button class="action-btn stop-btn" data-action="stop">■ Dừng</button>' : ''}
          ${!canStop ? '<button class="action-btn delete-btn" data-action="delete">× Xóa</button>' : ''}
        </div></td></tr>`;
    }).join('');
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
  }

  function renderOutput() {
    const lines = state.output.trim() ? state.output.trim().split(/\r?\n/) : [];
    $('success-output').value = lines.join('\n');
    $('output-count').textContent = `${lines.length} tài khoản`;
    $('output-empty').style.display = lines.length ? 'none' : 'flex';
    $('success-output').style.visibility = lines.length ? 'visible' : 'hidden';
    $('copy-output').disabled = !lines.length;
    $('export-output').disabled = !lines.length;
  }

  async function refreshOutput() {
    try {
      state.output = await api('/api/output');
      renderOutput();
    } catch (error) {
      toast(`Không tải được output: ${error.message}`, 'error');
    }
  }

  async function copyOutput() {
    if (!state.output.trim()) return;
    try {
      await writeClipboard(state.output.trim());
      toast('Đã copy toàn bộ tài khoản thành công.');
    } catch (_) {
      toast('Không thể copy tự động. Hãy chọn nội dung và copy thủ công.', 'error');
    }
  }

  async function writeClipboard(value) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return;
    }
    const fallback = document.createElement('textarea');
    fallback.value = value;
    fallback.setAttribute('readonly', '');
    fallback.style.cssText = 'position:fixed;inset:0 auto auto 0;opacity:0;pointer-events:none';
    document.body.appendChild(fallback);
    fallback.select();
    const copied = document.execCommand('copy');
    fallback.remove();
    window.getSelection()?.removeAllRanges();
    if (!copied) throw new Error('Clipboard unavailable');
  }

  async function copyFailed() {
    try {
      const output = String(await api('/api/output/errors')).trim();
      if (!output) return toast('Chưa có tài khoản lỗi để copy.', 'error');
      await writeClipboard(output);
      const count = output.split(/\r?\n/).filter(Boolean).length;
      toast(`Đã copy ${count} tài khoản lỗi bằng thông tin hiện hành.`);
    } catch (error) {
      toast(`Không copy được tài khoản lỗi: ${error.message}`, 'error');
    }
  }

  function openLaunchConfirmation() {
    const lines = $('combo-input').value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (!lines.length) return toast('Hãy nhập ít nhất một combo.', 'error');
    const proxies = proxyPool();
    const mode = modeValue();
    const info = MODE_LABELS[mode] || { title: mode, icon: '?', description: '' };
    const isDestructive = mode !== 'check_only';
    state.pendingLaunch = { lines, mode };
    $('confirm-accent').className = `confirm-accent ${isDestructive ? 'is-change' : 'is-check'}`;
    $('confirm-icon').textContent = info.icon;
    $('confirm-title').textContent = info.title;
    $('confirm-message').textContent = info.description;
    $('confirm-count').textContent = lines.length;
    $('confirm-concurrency').textContent = $('quick-concurrency').value;
    $('confirm-proxy').textContent = proxies.length ? `${proxies.length} PROXY XOAY VÒNG` : 'DIRECT';
    $('confirm-action').textContent = info.short;
    $('confirm-launch').className = `button ${isDestructive ? 'confirm-change' : 'confirm-check'}`;
    $('confirm-launch').textContent = isDestructive ? `Xác nhận — ${info.title}` : 'Đúng, chỉ kiểm tra';
    $('launch-confirm').showModal();
  }

  async function launch() {
    if (!state.pendingLaunch) return;
    const { lines, mode } = state.pendingLaunch;
    state.pendingLaunch = null;
    $('launch-confirm').close();
    $('launch-batch').disabled = true;
    try {
      const data = await api('/api/jobs', { method: 'POST', body: JSON.stringify({ lines, mode }) });
      data.jobs.forEach((job) => state.jobs.set(job.id, job));
      render();
      const info = MODE_LABELS[mode] || { title: mode };
      toast(`Đã nạp ${data.jobs.length} tài khoản — ${info.title}.`);
      $('queue').scrollIntoView({ behavior: 'smooth' });
    } catch (error) { toast(error.message, 'error'); }
    finally { $('launch-batch').disabled = false; }
  }

  async function jobAction(id, action) {
    try {
      if (action === 'logs') return openLogs(id);
      if (action === 'retry' || action === 'stop') {
        const data = await api(`/api/jobs/${id}/${action}`, { method: 'POST' });
        state.jobs.set(id, data.job); render();
      } else if (action === 'delete') {
        await api(`/api/jobs/${id}`, { method: 'DELETE' });
        state.jobs.delete(id); render();
      }
    } catch (error) { toast(error.message, 'error'); }
  }

  async function openLogs(id) {
    const job = state.jobs.get(id);
    if (!job) return;
    if (state.selectedJob === id) {
      closeInlineLog();
      return;
    }
    state.selectedJob = id;
    render();
    const panel = $('inline-log-panel');
    panel.style.display = 'flex';
    $('inline-log-title').textContent = job.email;
    const verifyFailed = isVerifyFailure(job);
    $('inline-log-status').innerHTML = `<span class="status ${job.status}${verifyFailed ? ' verify-failed' : ''}">${escapeHtml(statusLabel(job))}</span>${job.has_proxy ? `<span class="proxy-chip">PROXY #${job.proxy_slot} · ${escapeHtml(job.proxy_label)}</span>` : '<span class="proxy-chip direct">DIRECT</span>'}`;
    $('inline-log-checkpoint').hidden = !verifyFailed;
    $('inline-log-content').textContent = 'Đang tải log...';
    try {
      const data = await api(`/api/jobs/${id}/logs`);
      const logs = [...data.logs];
      if (job.error && !logs.some((line) => line.includes(job.error))) {
        logs.push(`[kết quả lỗi] ${job.error}`);
      }
      $('inline-log-content').textContent = logs.join('\n') || 'Chưa có log.';
      $('inline-log-content').scrollTop = $('inline-log-content').scrollHeight;
    } catch (error) { $('inline-log-content').textContent = error.message; }
  }

  function closeInlineLog() {
    $('inline-log-panel').style.display = 'none';
    state.selectedJob = null;
    render();
  }

  function openDrawer(id) {
    closeDrawers();
    $(id).classList.add('open'); $(id).setAttribute('aria-hidden', 'false');
    $('drawer-backdrop').classList.add('open');
  }

  function closeDrawers() {
    document.querySelectorAll('.drawer').forEach((drawer) => { drawer.classList.remove('open'); drawer.setAttribute('aria-hidden', 'true'); });
    $('drawer-backdrop').classList.remove('open');
  }

  function loadSettingsForm() {
    const concurrency = state.settings['twofa.max_concurrent'];
    $('setting-concurrency').value = concurrency;
    $('quick-concurrency').value = concurrency;
    $('setting-timeout').value = state.settings['twofa.job_timeout'];
    $('setting-auto-retry').checked = state.settings['twofa.auto_retry'];
    $('setting-retry-max').value = state.settings['twofa.auto_retry_max'];
    $('setting-retry-delay').value = state.settings['twofa.auto_retry_delay'];
    $('setting-proxy-pool').value = proxyPool().join('\n');
    updateProxySummary();
    resetProxyTest();
    renderMode();
  }

  function settingsPayload(maxConcurrent = state.settings['twofa.max_concurrent']) {
    return {
      max_concurrent: Number(maxConcurrent),
      job_timeout: Number(state.settings['twofa.job_timeout']),
      auto_retry: Boolean(state.settings['twofa.auto_retry']),
      auto_retry_max: Number(state.settings['twofa.auto_retry_max']),
      auto_retry_delay: Number(state.settings['twofa.auto_retry_delay']),
      change_enabled: Boolean(state.settings['twofa.change_enabled']),
      input_draft: $('combo-input').value,
      proxy_pool: proxyPool(),
    };
  }

  async function saveQuickConcurrency() {
    const input = $('quick-concurrency');
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 1 || value > 10) {
      input.value = state.settings['twofa.max_concurrent'];
      throw new Error('Số luồng phải từ 1 đến 10.');
    }
    if (value === Number(state.settings['twofa.max_concurrent'])) return;
    const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(settingsPayload(value)) });
    state.settings = data.settings;
    loadSettingsForm();
    toast(`Đã đổi sang ${value} luồng chạy đồng thời.`);
  }

  async function retryFailed() {
    const failed = [...state.jobs.values()].filter((job) => ['error', 'cancelled'].includes(job.status) && job.retryable !== false);
    if (!failed.length) return;
    const button = $('retry-failed');
    button.disabled = true;
    let retried = 0;
    try {
      for (const job of failed) {
        try {
          const data = await api(`/api/jobs/${job.id}/retry`, { method: 'POST' });
          state.jobs.set(job.id, data.job);
          retried += 1;
          render();
        } catch (error) {
          toast(`${job.email}: ${error.message}`, 'error');
        }
      }
      toast(`Đã đưa ${retried}/${failed.length} tài khoản lỗi vào chạy lại.`);
    } finally {
      render();
    }
  }

  async function saveSettings(event) {
    event.preventDefault();
    try {
      const payload = {
        max_concurrent: Number($('setting-concurrency').value),
        job_timeout: Number($('setting-timeout').value),
        auto_retry: $('setting-auto-retry').checked,
        auto_retry_max: Number($('setting-retry-max').value),
        auto_retry_delay: Number($('setting-retry-delay').value),
        change_enabled: Boolean(state.settings['twofa.change_enabled']),
        input_draft: $('combo-input').value,
        proxy_pool: proxyInputLines(),
      };
      const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
      state.settings = data.settings;
      loadSettingsForm();
      closeDrawers(); toast('Đã lưu cấu hình runtime vào SQLite.');
    } catch (error) { toast(error.message, 'error'); }
  }

  async function exportOutput() {
    try {
      const response = await fetch('/api/output', { headers: { 'X-Auth-Token': state.token } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'twofa-success.txt'; anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) { toast(error.message, 'error'); }
  }

  function connectEvents() {
    state.events?.close();
    state.events = new EventSource(`/api/events?token=${encodeURIComponent(state.token)}`);
    state.events.onopen = () => { $('connection-label').textContent = 'SẴN SÀNG'; };
    state.events.onerror = () => { $('connection-label').textContent = 'ĐANG KẾT NỐI'; };
    state.events.onmessage = ({ data }) => {
      const payload = JSON.parse(data);
      if (payload.type === 'snapshot') {
        state.jobs.clear(); payload.jobs.forEach((job) => state.jobs.set(job.id, job));
      } else if (payload.type === 'job') state.jobs.set(payload.job.id, payload.job);
      else if (payload.type === 'removed') state.jobs.delete(payload.id);
      render();
      refreshOutput();
    };
  }

  async function init() {
    try {
      const data = await fetch('/api/bootstrap').then((response) => response.json());
      state.token = data.token; state.settings = data.settings;
      $('combo-input').value = String(state.settings['twofa.input_draft'] || '');
      data.jobs.forEach((job) => state.jobs.set(job.id, job));
      loadSettingsForm(); updateEditor(); render(); renderOutput(); connectEvents(); await refreshOutput();
    } catch (_) { $('connection-label').textContent = 'MẤT KẾT NỐI'; toast('Không kết nối được dịch vụ tại máy.', 'error'); }
  }

  $('combo-input').addEventListener('input', scheduleDraftSave);
  $('combo-input').addEventListener('scroll', () => { $('line-numbers').scrollTop = $('combo-input').scrollTop; });
  document.querySelectorAll('.mode-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.activeMode = btn.dataset.mode;
      renderMode();
    });
  });
  $('quick-concurrency').addEventListener('change', async () => {
    try { await saveQuickConcurrency(); } catch (error) { toast(error.message, 'error'); }
  });
  $('setting-proxy-pool').addEventListener('input', () => { updateProxySummary(); resetProxyTest(); });
  $('test-proxies').addEventListener('click', testProxies);
  $('launch-batch').addEventListener('click', async () => {
    try { await saveQuickConcurrency(); openLaunchConfirmation(); } catch (error) { toast(error.message, 'error'); }
  });
  $('confirm-launch').addEventListener('click', launch);
  $('cancel-launch').addEventListener('click', () => { state.pendingLaunch = null; $('launch-confirm').close(); });
  $('retry-failed').addEventListener('click', retryFailed);
  $('copy-failed').addEventListener('click', copyFailed);
  $('job-list').addEventListener('click', (event) => {
    const button = event.target.closest('[data-action]');
    const row = event.target.closest('tr');
    if (button && row) return jobAction(row.dataset.id, button.dataset.action);
    if (row && row.dataset.id) openLogs(row.dataset.id);
  });
  $('close-inline-log').addEventListener('click', closeInlineLog);
  document.querySelectorAll('.filter').forEach((button) => button.addEventListener('click', () => {
    document.querySelectorAll('.filter').forEach((item) => item.classList.remove('active'));
    button.classList.add('active'); state.filter = button.dataset.filter; render();
  }));
  document.querySelectorAll('[data-target]').forEach((button) => button.addEventListener('click', () => $(button.dataset.target).scrollIntoView({ behavior: 'smooth' })));
  $('open-settings').addEventListener('click', () => { loadSettingsForm(); openDrawer('settings-drawer'); });
  $('open-proxy-settings').addEventListener('click', () => { loadSettingsForm(); openDrawer('settings-drawer'); $('setting-proxy-pool').focus(); });
  $('close-detail').addEventListener('click', closeDrawers); $('close-settings').addEventListener('click', closeDrawers); $('drawer-backdrop').addEventListener('click', closeDrawers);
  $('settings-form').addEventListener('submit', saveSettings);
  $('copy-output').addEventListener('click', copyOutput);
  $('export-output').addEventListener('click', exportOutput);
  $('nav-output').addEventListener('click', () => $('output-panel').scrollIntoView({ behavior: 'smooth' }));
  $('stop-all').addEventListener('click', async () => { try { await api('/api/jobs/stop-all', { method: 'POST' }); toast('Đã gửi lệnh dừng toàn bộ.'); } catch (error) { toast(error.message, 'error'); } });
  $('clear-all').addEventListener('click', async () => { try { await api('/api/jobs', { method: 'DELETE' }); state.jobs.clear(); render(); await refreshOutput(); toast('Đã dọn danh sách.'); } catch (error) { toast(error.message, 'error'); } });
  updateEditor(); renderOutput(); init();
})();
