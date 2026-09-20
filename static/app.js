(() => {
  'use strict';

  const state = {
    csrfToken: '',
    user: null,
    capabilities: null,
    jobs: new Map(),
    filter: 'all',
    settings: {},
    events: null,
    output: '',
    pendingLaunch: null,
    activeMode: 'check_only',
    selectedJob: null,
    pollTimer: null,
    isPolling: false,
    pollEpoch: 0,
    activeLogTimer: null,
  };

  const $ = (id) => document.getElementById(id);
  const statusLabels = {
    queued: 'ĐANG CHỜ',
    running: 'ĐANG CHẠY',
    success: 'THÀNH CÔNG',
    error: 'LỖI',
    cancelled: 'ĐÃ DỪNG',
  };
  const errorLabels = {
    account_die: 'TÀI KHOẢN DIE',
    invalid_credentials: 'SAI MẬT KHẨU / 2FA',
    technical_error: 'LỖI KỸ THUẬT',
  };
  const MODE_LABELS = {
    check_only: {
      short: 'CHỈ KIỂM TRA',
      title: 'Kiểm tra tài khoản',
      icon: '✓',
      description: 'Xác định trạng thái Live, Free hoặc Plus mà không thay đổi thông tin.',
    },
    change_2fa: {
      short: 'ĐỔI 2FA',
      title: 'Cập nhật 2FA',
      icon: '⟳',
      description: 'Tạo khóa TOTP mới, sau đó đăng nhập lại để kiểm tra.',
    },
    change_password: {
      short: 'ĐỔI MẬT KHẨU',
      title: 'Cập nhật mật khẩu',
      icon: '🔑',
      description: 'Tạo mật khẩu mới, giữ nguyên 2FA và xác minh phiên đăng nhập.',
    },
    change_password_and_2fa: {
      short: 'MẬT KHẨU + 2FA',
      title: 'Cập nhật toàn bộ',
      icon: '⬡',
      description: 'Thay mật khẩu và khóa TOTP trong cùng một quy trình xác minh.',
    },
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

  function cleanErrorMessage(raw) {
    if (!raw) return '';
    const str = String(raw).trim();
    if (str.includes('HTTP 401') || str.includes('Login failed')) return 'Sai mật khẩu hoặc 2FA (HTTP 401)';
    if (str.includes('HTTP 400')) return 'Lỗi tham số yêu cầu (HTTP 400)';
    if (str.includes('HTTP 403') || str.includes('Cloudflare')) return 'Bị chặn IP / Cloudflare (HTTP 403)';
    if (str.includes('HTTP 429')) return 'Bị giới hạn tần suất (HTTP 429)';
    if (str.includes('TimeoutError') || str.includes('Hết thời gian')) return 'Quá thời gian kết nối (Timeout)';
    if (str.includes('Đã dừng')) return 'Đã dừng bởi người dùng';
    const jsonIndex = str.indexOf('{');
    if (jsonIndex > 10) {
      return str.slice(0, jsonIndex).replace(/[-:]\s*$/, '').trim();
    }
    return str.length > 45 ? `${str.slice(0, 42)}…` : str;
  }

  function accountCheck(job) {
    const errorSummary = cleanErrorMessage(job.error);
    if (isVerifyFailure(job)) {
      return {
        label: '2FA ĐÃ ĐỔI',
        className: 'verify-failed',
        detail: errorSummary || 'Đăng nhập verify bằng 2FA mới thất bại',
      };
    }
    if (job.account_state === 'die') {
      return { label: 'DIE', className: 'die', detail: errorSummary || 'Tài khoản đã bị vô hiệu hóa' };
    }
    if (job.account_state === 'live') {
      return {
        label: `LIVE · ${planLabel(job)}`,
        className: 'live',
        detail: `Gói từ ${job.plan_source || 'session'}`,
      };
    }
    if (job.error_kind === 'invalid_credentials') {
      return {
        label: 'CHƯA XÁC MINH',
        className: 'unknown',
        detail: errorSummary || 'Thông tin đăng nhập hoặc 2FA không đúng',
      };
    }
    return { label: 'CHƯA RÕ', className: 'unknown', detail: errorSummary || 'Chưa kiểm tra xong' };
  }

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    const method = (options.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method) && state.csrfToken) {
      headers['X-CSRF-Token'] = state.csrfToken;
    }
    if (options.body && typeof options.body === 'string' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(path, { ...options, headers });
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const errJson = await response.json();
        message = errJson.detail || message;
      } catch (_) { /* plain error */ }
      const error = new Error(message);
      error.status = response.status;
      throw error;
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
    $('line-numbers').textContent = Array.from(
      { length: Math.max(1, value.split(/\r?\n/).length) },
      (_, i) => i + 1
    ).join('\n');
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

  function proxyBindings() {
    return (state.settings && typeof state.settings['twofa.proxy_bindings'] === 'object')
      ? state.settings['twofa.proxy_bindings']
      : {};
  }

  function updateProxySummary() {
    const savedCount = proxyPool().length;
    const inputCount = proxyInputLines().length;
    const mode = state.settings?.['twofa.proxy_mode'] || 'random_per_account';
    const modeLabel = mode === 'manual_per_worker' ? 'CỐ ĐỊNH' : 'RANDOM';
    $('proxy-summary').textContent = savedCount ? `${savedCount} PROXY · ${modeLabel}` : 'DIRECT';
    $('setting-proxy-count').textContent = `${inputCount} proxy`;
  }

  function renderWorkerProxyBindings() {
    const modeSel = $('setting-proxy-mode');
    const mode = modeSel ? modeSel.value : 'random_per_account';
    const container = $('proxy-worker-bindings-container');
    const list = $('proxy-worker-bindings-list');
    const help = $('proxy-mode-help');
    const statusText = $('bindings-status-text');
    if (!container || !list) return;

    if (mode === 'random_per_account') {
      container.hidden = true;
      if (help) help.textContent = 'Worker tự động đổi sang proxy rảnh ngẫu nhiên khi sang tài khoản mới (tránh bị OpenAI rate-limit).';
      return;
    }

    container.hidden = false;
    if (help) help.textContent = 'Mỗi Luồng (Worker) được gán cố định 1 proxy duy nhất trong suốt quá trình chạy.';

    const concurrency = Number($('setting-concurrency').value) || 1;
    const lines = proxyInputLines();
    const currentBindings = proxyBindings();

    if (!lines.length) {
      list.innerHTML = '<div style="color:var(--danger);font-size:0.72rem;padding:8px 4px;font-family:var(--font-mono);">⚠️ Vui lòng dán danh sách proxy vào ô bên trên trước khi phân bổ luồng.</div>';
      if (statusText) statusText.textContent = '0 proxy';
      return;
    }

    // Helper rút gọn hiển thị host:port sạch đẹp
    const cleanProxyLabel = (raw) => {
      try {
        let text = raw.trim();
        if (text.includes('://')) {
          text = text.split('://')[1];
        }
        if (text.includes('@')) {
          text = text.split('@')[1];
        } else {
          const parts = text.split(':');
          if (parts.length >= 2) {
            text = `${parts[0]}:${parts[1]}`;
          }
        }
        return text;
      } catch (_) {
        return raw.slice(0, 24);
      }
    };

    let boundCount = 0;
    let html = '';
    for (let slot = 1; slot <= concurrency; slot++) {
      const boundVal = currentBindings[String(slot)] || currentBindings[slot] || slot;
      const options = lines.map((line, idx) => {
        const slotIdx = idx + 1;
        const isSelected = String(boundVal) === String(slotIdx) || boundVal === line;
        if (isSelected) boundCount++;
        const safeHostPort = cleanProxyLabel(line);
        return `<option value="${slotIdx}" ${isSelected ? 'selected' : ''}>Proxy #${slotIdx} · ${escapeHtml(safeHostPort)}</option>`;
      }).join('');

      html += `
        <div class="worker-binding-row">
          <span class="worker-slot-badge">Luồng #${slot}</span>
          <select class="worker-binding-select" data-slot="${slot}">
            ${options}
          </select>
        </div>
      `;
    }
    list.innerHTML = html;
    if (statusText) {
      statusText.textContent = `${Math.min(boundCount, concurrency)}/${concurrency} luồng đã gán`;
    }

    // Lắng nghe thay đổi chọn proxy của từng luồng
    list.querySelectorAll('.worker-binding-select').forEach((sel) => {
      sel.addEventListener('change', () => {
        if (statusText) {
          statusText.textContent = `${concurrency}/${concurrency} luồng đã gán`;
        }
      });
    });
  }

  function collectWorkerBindings() {
    const bindings = {};
    const selects = document.querySelectorAll('.worker-binding-select');
    selects.forEach((sel) => {
      const slot = sel.dataset.slot;
      if (slot) bindings[slot] = Number(sel.value) || sel.value;
    });
    return bindings;
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

  function formatStartTime(timestamp) {
    if (!timestamp) {
      return '<span class="time-capsule-pill pending">Chờ chạy</span>';
    }
    const date = new Date(timestamp * 1000);
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    const dateStr = `${day}/${month}/${year}`;
    const timeStr = `${hours}:${minutes}:${seconds}`;

    return `<div class="time-capsule-cell" title="Bắt đầu: ${dateStr} ${timeStr}">
      <span class="time-capsule-date"><span class="date-icon">📅</span>${dateStr}</span>
      <span class="time-capsule-pill"><span class="time-icon">⏱</span>${timeStr}</span>
    </div>`;
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
        <td class="account"><strong>${escapeHtml(job.email)}</strong><span>${job.id.slice(0, 10).toUpperCase()} · <b class="job-mode mode-${job.mode}">${escapeHtml(modeShort)}</b></span>${job.has_proxy ? `<small class="proxy-assignment">${job.worker_slot ? `Luồng #${job.worker_slot} · ` : ''}PROXY #${job.proxy_slot} · ${escapeHtml(job.proxy_label)}</small>` : ''}</td>
        <td><span class="status ${job.status}${verifyFailed ? ' verify-failed' : ''} ${job.plan ? `plan-${escapeHtml(job.plan)}` : ''}">${escapeHtml(statusLabel(job))}</span></td>
        <td>${formatStartTime(job.started_at)}</td>
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
    return String(value || '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
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
    if (!state.user) return;
    try {
      state.output = await api('/api/output');
      renderOutput();
    } catch (error) {
      if (error.status !== 401) {
        toast(`Không tải được output: ${error.message}`, 'error');
      }
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

    if (state.user && state.user.role !== 'admin' && lines.length > 50) {
      return toast('Cộng tác viên chỉ được gửi tối đa 50 tài khoản mỗi lần.', 'error');
    }

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
    const proxyCount = proxies.length;
    const pMode = state.settings?.['twofa.proxy_mode'] || 'random_per_account';
    let proxyConfirmText = 'DIRECT';
    if (state.user?.role === 'admin' && proxyCount) {
      if (pMode === 'manual_per_worker') {
        proxyConfirmText = `CỐ ĐỊNH · ${$('quick-concurrency').value} luồng`;
      } else {
        proxyConfirmText = `RANDOM · ${proxyCount} proxy`;
      }
    } else if (proxyCount) {
      proxyConfirmText = 'HỆ THỐNG GÁN TỰ ĐỘNG';
    }
    $('confirm-proxy').textContent = proxyConfirmText;
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

  function updateInlineLogHeader(job) {
    if (!job || state.selectedJob !== job.id) return;
    $('inline-log-title').textContent = job.email;
    const verifyFailed = isVerifyFailure(job);
    const timeChip = job.started_at
      ? `<span class="proxy-chip time-chip" title="Thời gian bắt đầu">⏱ ${new Date(job.started_at * 1000).toLocaleTimeString('vi-VN')}</span>`
      : '';
    const proxyChip = job.has_proxy
      ? `<span class="proxy-chip">${job.worker_slot ? `Luồng #${job.worker_slot} · ` : ''}PROXY #${job.proxy_slot} · ${escapeHtml(job.proxy_label)}${job.proxy_mode === 'manual_per_worker' ? ' [CỐ ĐỊNH]' : ''}</span>`
      : '<span class="proxy-chip direct">DIRECT</span>';
    $('inline-log-status').innerHTML = `<span class="status ${job.status}${verifyFailed ? ' verify-failed' : ''}">${escapeHtml(statusLabel(job))}</span>${timeChip}${proxyChip}`;
    const stopBtn = $('btn-stop-inline-job');
    if (stopBtn) {
      stopBtn.hidden = !['queued', 'running'].includes(job.status);
    }
    $('inline-log-checkpoint').hidden = !verifyFailed;
  }

  async function fetchActiveLogs(id) {
    if (state.selectedJob !== id) return;
    try {
      const data = await api(`/api/jobs/${id}/logs`);
      if (state.selectedJob !== id) return;
      const job = state.jobs.get(id);
      const logs = [...(data.logs || [])];
      if (job?.error && !logs.some((line) => line.includes(job.error))) {
        logs.push(`[kết quả lỗi] ${job.error}`);
      }
      $('inline-log-content').textContent = logs.join('\n') || 'Chưa có log.';
      $('inline-log-content').scrollTop = $('inline-log-content').scrollHeight;
    } catch (error) {
      if (state.selectedJob === id) {
        $('inline-log-content').textContent = error.message;
      }
    }
  }

  function refreshActiveLogDebounced(id, delayMs = 300, immediate = false) {
    if (state.selectedJob !== id) return;
    if (state.activeLogTimer) {
      clearTimeout(state.activeLogTimer);
      state.activeLogTimer = null;
    }
    if (immediate) {
      fetchActiveLogs(id);
    } else {
      state.activeLogTimer = setTimeout(() => {
        state.activeLogTimer = null;
        fetchActiveLogs(id);
      }, delayMs);
    }
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
    updateInlineLogHeader(job);
    $('inline-log-content').textContent = 'Đang tải log...';
    await fetchActiveLogs(id);
  }

  function closeInlineLog() {
    if (state.activeLogTimer) {
      clearTimeout(state.activeLogTimer);
      state.activeLogTimer = null;
    }
    $('inline-log-panel').style.display = 'none';
    state.selectedJob = null;
    render();
  }

  function openDrawer(id) {
    closeDrawers();
    $(id).classList.add('open');
    $(id).setAttribute('aria-hidden', 'false');
    $('drawer-backdrop').classList.add('open');
  }

  function closeDrawers() {
    document.querySelectorAll('.drawer').forEach((drawer) => {
      drawer.classList.remove('open');
      drawer.setAttribute('aria-hidden', 'true');
    });
    $('drawer-backdrop').classList.remove('open');
  }

  function loadSettingsForm() {
    if (!state.settings) return;
    const concurrency = state.settings['twofa.max_concurrent'] || 3;
    $('setting-concurrency').value = concurrency;
    $('quick-concurrency').value = concurrency;
    $('setting-timeout').value = state.settings['twofa.job_timeout'] || 180;
    $('setting-auto-retry').checked = Boolean(state.settings['twofa.auto_retry']);
    $('setting-retry-max').value = state.settings['twofa.auto_retry_max'] ?? 2;
    $('setting-retry-delay').value = state.settings['twofa.auto_retry_delay'] ?? 5;
    $('setting-proxy-pool').value = proxyPool().join('\n');
    if ($('setting-proxy-mode')) {
      $('setting-proxy-mode').value = state.settings['twofa.proxy_mode'] || 'random_per_account';
    }
    renderWorkerProxyBindings();
    updateProxySummary();
    resetProxyTest();
    renderMode();
  }

  function settingsPayload(maxConcurrent = state.settings['twofa.max_concurrent']) {
    return {
      max_concurrent: Number(maxConcurrent),
      job_timeout: Number(state.settings['twofa.job_timeout'] || 180),
      auto_retry: Boolean(state.settings['twofa.auto_retry']),
      auto_retry_max: Number(state.settings['twofa.auto_retry_max'] ?? 2),
      auto_retry_delay: Number(state.settings['twofa.auto_retry_delay'] ?? 5),
      change_enabled: Boolean(state.settings['twofa.change_enabled']),
      input_draft: '',
      proxy_pool: proxyPool(),
      proxy_mode: state.settings['twofa.proxy_mode'] || 'random_per_account',
      proxy_bindings: state.settings['twofa.proxy_bindings'] || {},
    };
  }

  async function saveQuickConcurrency() {
    if (state.user?.role !== 'admin') return;
    const input = $('quick-concurrency');
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 1 || value > 10) {
      input.value = state.settings['twofa.max_concurrent'] || 3;
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
    if (state.user?.role !== 'admin') {
      return toast('Chỉ Quản trị viên mới được sửa thiết lập', 'error');
    }
    try {
      const mode = $('setting-proxy-mode')?.value || 'random_per_account';
      const bindings = mode === 'manual_per_worker' ? collectWorkerBindings() : (state.settings['twofa.proxy_bindings'] || {});
      const payload = {
        max_concurrent: Number($('setting-concurrency').value),
        job_timeout: Number($('setting-timeout').value),
        auto_retry: $('setting-auto-retry').checked,
        auto_retry_max: Number($('setting-retry-max').value),
        auto_retry_delay: Number($('setting-retry-delay').value),
        change_enabled: Boolean(state.settings['twofa.change_enabled']),
        input_draft: '',
        proxy_pool: proxyInputLines(),
        proxy_mode: mode,
        proxy_bindings: bindings,
      };
      const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
      state.settings = data.settings;
      loadSettingsForm();
      closeDrawers();
      toast('Đã lưu cấu hình proxy và luồng runtime vào SQLite.');
    } catch (error) { toast(error.message, 'error'); }
  }

  async function exportOutput() {
    try {
      const response = await fetch('/api/output');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'twofa-success.txt';
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) { toast(error.message, 'error'); }
  }

  function resetSensitiveState() {
    stopPollingFallback();
    if (state.activeLogTimer) {
      clearTimeout(state.activeLogTimer);
      state.activeLogTimer = null;
    }
    state.csrfToken = '';
    state.user = null;
    state.capabilities = null;
    state.jobs.clear();
    state.output = '';
    state.selectedJob = null;
    if (state.events) {
      state.events.close();
      state.events = null;
    }
    if ($('btn-login-trigger')) $('btn-login-trigger').hidden = false;
    if ($('user-pill')) $('user-pill').hidden = true;
    if ($('btn-open-users-pill')) $('btn-open-users-pill').hidden = true;
    $('nav-users').hidden = true;
    $('open-settings').style.display = 'none';
    $('open-proxy-settings').style.display = 'none';
    const concControl = $('quick-concurrency').closest('.concurrency-control');
    if (concControl) concControl.style.display = 'none';
    $('connection-label').textContent = 'CHƯA ĐĂNG NHẬP';
    closeDrawers();
    render();
    renderOutput();
  }

  function applyUserSession(user, csrfToken, capabilities) {
    state.user = user;
    state.csrfToken = csrfToken;
    state.capabilities = capabilities || {};
    if ($('btn-login-trigger')) $('btn-login-trigger').hidden = true;
    if ($('user-pill')) $('user-pill').hidden = false;
    $('user-display-name').textContent = user.username;
    $('user-role-badge').textContent = user.role.toUpperCase();
    $('user-role-badge').className = `user-role-badge role-${user.role}`;

    const isAdmin = user.role === 'admin';
    $('nav-users').hidden = !isAdmin;
    if ($('btn-open-users-pill')) $('btn-open-users-pill').hidden = !isAdmin;
    $('open-settings').style.display = isAdmin ? 'flex' : 'none';
    $('open-proxy-settings').style.display = isAdmin ? 'inline-flex' : 'none';
    const concControl = $('quick-concurrency').closest('.concurrency-control');
    if (concControl) concControl.style.display = isAdmin ? 'inline-flex' : 'none';
  }

  function openLoginModal() {
    $('login-error').hidden = true;
    $('login-password').value = '';
    try { $('login-modal').showModal(); } catch (_) {}
  }

  function closeLoginModal() {
    try { $('login-modal').close(); } catch (_) {}
  }

  async function handleLogin(e) {
    e.preventDefault();
    const username = $('login-username').value.trim();
    const password = $('login-password').value;
    $('login-error').hidden = true;
    $('login-submit').disabled = true;
    try {
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      closeLoginModal();
      $('login-password').value = '';
      await init();
      toast(`Đăng nhập thành công!`);
    } catch (err) {
      $('login-error').textContent = err.message;
      $('login-error').hidden = false;
    } finally {
      $('login-submit').disabled = false;
    }
  }

  async function handleLogout() {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } catch (_) {}
    resetSensitiveState();
    openLoginModal();
    toast('Đã đăng xuất khỏi hệ thống.');
  }

  function openChangePassModal() {
    $('change-pass-error').hidden = true;
    $('cp-old-password').value = '';
    $('cp-new-password').value = '';
    $('cp-confirm-password').value = '';
    try { $('change-pass-modal').showModal(); } catch (_) {}
  }

  function closeChangePassModal() {
    try { $('change-pass-modal').close(); } catch (_) {}
  }

  async function handleChangePassword(e) {
    e.preventDefault();
    const old_password = $('cp-old-password').value;
    const new_password = $('cp-new-password').value;
    const confirm_password = $('cp-confirm-password').value;

    if (new_password !== confirm_password) {
      $('change-pass-error').textContent = 'Xác nhận mật khẩu mới không khớp.';
      $('change-pass-error').hidden = false;
      return;
    }

    $('change-pass-error').hidden = true;
    $('submit-change-pass').disabled = true;
    try {
      await api('/api/auth/password', {
        method: 'PUT',
        body: JSON.stringify({ old_password, new_password }),
      });
      closeChangePassModal();
      toast('Đổi mật khẩu thành công!');
    } catch (err) {
      $('change-pass-error').textContent = err.message;
      $('change-pass-error').hidden = false;
    } finally {
      $('submit-change-pass').disabled = false;
    }
  }

  // --- Quản lý CTV (Admin) ---
  function formatUserDate(val) {
    if (!val) return 'Chưa login';
    let d;
    if (typeof val === 'number') {
      d = new Date(val * 1000);
    } else {
      d = new Date(val);
    }
    if (isNaN(d.getTime())) return 'Chưa login';
    return new Intl.DateTimeFormat('vi-VN', {
      dateStyle: 'short',
      timeStyle: 'short',
      timeZone: 'Asia/Ho_Chi_Minh',
    }).format(d);
  }

  async function loadCollaborators() {
    const listBody = $('collaborators-list');
    listBody.innerHTML = '<tr><td colspan="4" class="text-muted">Đang tải danh sách...</td></tr>';
    try {
      const data = await api('/api/admin/users');
      if (!data.users || !data.users.length) {
        listBody.innerHTML = '<tr><td colspan="4" class="text-muted">Chưa có cộng tác viên nào.</td></tr>';
        return;
      }
      listBody.innerHTML = data.users.map((u) => {
        const lastLogin = formatUserDate(u.last_login_at);
        const isActive = u.status === 'active';
        return `<tr data-user-id="${u.id}" data-username="${escapeHtml(u.username)}" data-status="${u.status}">
          <td><strong>${escapeHtml(u.username)}</strong></td>
          <td><span class="user-status-badge is-${u.status}">${isActive ? 'HOẠT ĐỘNG' : 'ĐÃ KHÓA'}</span></td>
          <td><small>${escapeHtml(lastLogin)}</small></td>
          <td>
            <div class="user-actions">
              <button class="user-action-small" data-user-action="reset-pass" title="Đổi mật khẩu">Đổi pass</button>
              <button class="user-action-small ${isActive ? 'danger' : ''}" data-user-action="toggle-status">
                ${isActive ? 'Khóa' : 'Mở khóa'}
              </button>
              <button class="user-action-small danger" data-user-action="delete-user" title="Xóa vĩnh viễn CTV">Xóa</button>
            </div>
          </td>
        </tr>`;
      }).join('');
    } catch (err) {
      listBody.innerHTML = `<tr><td colspan="4" class="auth-error">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  function openCreateUserModal() {
    $('cu-error').hidden = true;
    $('cu-username').value = '';
    $('cu-password').value = '';
    try { $('create-user-modal').showModal(); } catch (_) {}
  }

  function closeCreateUserModal() {
    try { $('create-user-modal').close(); } catch (_) {}
  }

  async function handleCreateUser(e) {
    e.preventDefault();
    const username = $('cu-username').value.trim();
    const password = $('cu-password').value;
    $('cu-error').hidden = true;
    $('submit-create-user').disabled = true;
    try {
      await api('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      closeCreateUserModal();
      toast(`Đã tạo cộng tác viên ${username}`);
      await loadCollaborators();
    } catch (err) {
      $('cu-error').textContent = err.message;
      $('cu-error').hidden = false;
    } finally {
      $('submit-create-user').disabled = false;
    }
  }

  function openAdminResetPassModal(userId, username) {
    $('arp-user-id').value = userId;
    $('arp-subtitle').textContent = `Đặt lại mật khẩu cho tài khoản ${username}`;
    $('arp-password').value = '';
    $('arp-error').hidden = true;
    try { $('admin-reset-pass-modal').showModal(); } catch (_) {}
  }

  function closeAdminResetPassModal() {
    try { $('admin-reset-pass-modal').close(); } catch (_) {}
  }

  async function handleAdminResetPass(e) {
    e.preventDefault();
    const userId = $('arp-user-id').value;
    const password = $('arp-password').value;
    $('arp-error').hidden = true;
    $('submit-arp').disabled = true;
    try {
      await api(`/api/admin/users/${userId}/password`, {
        method: 'PUT',
        body: JSON.stringify({ password }),
      });
      closeAdminResetPassModal();
      toast('Đã cập nhật mật khẩu mới cho CTV thành công!');
    } catch (err) {
      $('arp-error').textContent = err.message;
      $('arp-error').hidden = false;
    } finally {
      $('submit-arp').disabled = false;
    }
  }

  async function handleToggleUserStatus(userId, currentStatus) {
    const nextStatus = currentStatus === 'active' ? 'inactive' : 'active';
    const actionLabel = nextStatus === 'inactive' ? 'khóa' : 'kích hoạt lại';
    if (!confirm(`Bạn có chắc muốn ${actionLabel} tài khoản CTV này?`)) return;
    try {
      await api(`/api/admin/users/${userId}/status`, {
        method: 'PUT',
        body: JSON.stringify({ status: nextStatus }),
      });
      toast(`Đã ${actionLabel} tài khoản CTV.`);
      await loadCollaborators();
    } catch (err) {
      toast(`Lỗi: ${err.message}`, 'error');
    }
  }

  async function handleDeleteUser(userId, username) {
    if (!confirm(`Bạn có chắc muốn XÓA VĨNH VIỄN cộng tác viên "${username}" không?\nToàn bộ phiên đăng nhập của CTV này sẽ bị hủy ngay lập tức.`)) return;
    try {
      await api(`/api/admin/users/${userId}`, { method: 'DELETE' });
      toast(`Đã xóa vĩnh viễn cộng tác viên ${username}`);
      await loadCollaborators();
    } catch (err) {
      toast(`Lỗi: ${err.message}`, 'error');
    }
  }

  function hasActiveJobs() {
    for (const job of state.jobs.values()) {
      if (['queued', 'running'].includes(job.status)) return true;
    }
    return false;
  }

  function stopPollingFallback() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
    state.pollEpoch += 1;
    state.isPolling = false;
  }

  function startPollingFallback() {
    if (state.pollTimer) return;
    if (!hasActiveJobs()) return;

    state.pollTimer = setInterval(async () => {
      if (state.isPolling) return;
      if (!hasActiveJobs()) {
        stopPollingFallback();
        return;
      }
      const currentEpoch = state.pollEpoch;
      state.isPolling = true;
      try {
        const data = await api('/api/bootstrap');
        // Nếu trong lúc chờ response mà SSE đã hồi phục (epoch tăng), bỏ qua response này
        if (currentEpoch !== state.pollEpoch) return;

        (data.jobs || []).forEach((job) => state.jobs.set(job.id, job));
        render();
        if (state.selectedJob) {
          const currentJob = state.jobs.get(state.selectedJob);
          if (currentJob) {
            updateInlineLogHeader(currentJob);
            fetchActiveLogs(state.selectedJob);
          }
        }
      } catch (_) {
        // Lỗi mạng khi poll -> giữ yên và chờ lần tiếp theo
      } finally {
        state.isPolling = false;
      }
    }, 3000);
  }

  function connectEvents() {
    state.events?.close();
    state.events = new EventSource('/api/events');
    state.events.onopen = () => {
      $('connection-label').textContent = 'SẴN SÀNG';
      stopPollingFallback();
    };
    state.events.onerror = () => {
      $('connection-label').textContent = 'ĐANG KẾT NỐI';
      startPollingFallback();
    };
    state.events.onmessage = ({ data }) => {
      try {
        const payload = JSON.parse(data);
        if (payload.type === 'auth_revoked') {
          toast('Phiên đăng nhập đã kết thúc hoặc tài khoản bị khóa.', 'error');
          resetSensitiveState();
          openLoginModal();
          return;
        }
        if (payload.type === 'snapshot') {
          state.jobs.clear();
          payload.jobs.forEach((job) => state.jobs.set(job.id, job));
        } else if (payload.type === 'job') {
          state.jobs.set(payload.job.id, payload.job);
          if (state.selectedJob === payload.job.id) {
            updateInlineLogHeader(payload.job);
            const isTerminal = ['success', 'error', 'cancelled'].includes(payload.job.status);
            refreshActiveLogDebounced(payload.job.id, 300, isTerminal);
          }
        } else if (payload.type === 'removed') {
          state.jobs.delete(payload.id);
          if (state.selectedJob === payload.id) {
            closeInlineLog();
          }
        }
        render();
        refreshOutput();
      } catch (err) {
        console.error('SSE Error:', err);
      }
    };
  }

  async function init() {
    try {
      const data = await api('/api/bootstrap');
      applyUserSession(data.user, data.csrf_token, data.capabilities);
      state.settings = data.settings || {};
      state.jobs.clear();
      data.jobs.forEach((job) => state.jobs.set(job.id, job));
      loadSettingsForm();
      updateEditor();
      render();
      renderOutput();
      connectEvents();
      await refreshOutput();
    } catch (err) {
      resetSensitiveState();
      openLoginModal();
    }
  }

  // --- Listeners ---
  $('combo-input').addEventListener('input', updateEditor);
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
  $('setting-proxy-pool').addEventListener('input', () => {
    renderWorkerProxyBindings();
    updateProxySummary();
    resetProxyTest();
  });
  $('setting-proxy-mode')?.addEventListener('change', () => {
    renderWorkerProxyBindings();
    updateProxySummary();
  });
  $('setting-concurrency')?.addEventListener('input', () => {
    renderWorkerProxyBindings();
  });
  $('test-proxies').addEventListener('click', testProxies);
  $('launch-batch').addEventListener('click', async () => {
    try {
      if (state.user?.role === 'admin') {
        await saveQuickConcurrency();
      }
      openLaunchConfirmation();
    } catch (error) { toast(error.message, 'error'); }
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
  $('btn-stop-inline-job')?.addEventListener('click', async () => {
    if (!state.selectedJob) return;
    await jobAction(state.selectedJob, 'stop');
    const updatedJob = state.jobs.get(state.selectedJob);
    if (updatedJob && $('btn-stop-inline-job')) {
      $('btn-stop-inline-job').hidden = !['queued', 'running'].includes(updatedJob.status);
      const verifyFailed = isVerifyFailure(updatedJob);
      const proxyChip = updatedJob.has_proxy
        ? `<span class="proxy-chip">${updatedJob.worker_slot ? `Luồng #${updatedJob.worker_slot} · ` : ''}PROXY #${updatedJob.proxy_slot} · ${escapeHtml(updatedJob.proxy_label)}${updatedJob.proxy_mode === 'manual_per_worker' ? ' [CỐ ĐỊNH]' : ''}</span>`
        : '<span class="proxy-chip direct">DIRECT</span>';
      $('inline-log-status').innerHTML = `<span class="status ${updatedJob.status}${verifyFailed ? ' verify-failed' : ''}">${escapeHtml(statusLabel(updatedJob))}</span>${proxyChip}`;
    }
  });
  document.querySelectorAll('.filter').forEach((button) => button.addEventListener('click', () => {
    document.querySelectorAll('.filter').forEach((item) => item.classList.remove('active'));
    button.classList.add('active');
    state.filter = button.dataset.filter;
    render();
  }));
  document.querySelectorAll('[data-target]').forEach((button) => button.addEventListener('click', () => $(button.dataset.target).scrollIntoView({ behavior: 'smooth' })));
  $('open-settings').addEventListener('click', () => {
    if (state.user?.role !== 'admin') return;
    loadSettingsForm();
    openDrawer('settings-drawer');
  });
  $('open-proxy-settings').addEventListener('click', () => {
    if (state.user?.role !== 'admin') return;
    loadSettingsForm();
    openDrawer('settings-drawer');
    $('setting-proxy-pool').focus();
  });
  $('close-detail').addEventListener('click', closeDrawers);
  $('close-settings').addEventListener('click', closeDrawers);
  $('close-users').addEventListener('click', closeDrawers);
  $('drawer-backdrop').addEventListener('click', closeDrawers);
  $('settings-form').addEventListener('submit', saveSettings);
  $('copy-output').addEventListener('click', copyOutput);
  $('export-output').addEventListener('click', exportOutput);
  $('nav-output').addEventListener('click', () => $('output-panel').scrollIntoView({ behavior: 'smooth' }));
  $('stop-all').addEventListener('click', async () => {
    try {
      await api('/api/jobs/stop-all', { method: 'POST' });
      toast('Đã gửi lệnh dừng toàn bộ.');
    } catch (error) { toast(error.message, 'error'); }
  });
  $('clear-all').addEventListener('click', async () => {
    try {
      await api('/api/jobs', { method: 'DELETE' });
      state.jobs.clear();
      render();
      await refreshOutput();
      toast('Đã dọn danh sách.');
    } catch (error) { toast(error.message, 'error'); }
  });

  // Auth & CTV Listeners
  $('btn-login-trigger')?.addEventListener('click', openLoginModal);
  $('close-login')?.addEventListener('click', closeLoginModal);
  $('login-form').addEventListener('submit', handleLogin);
  $('btn-logout').addEventListener('click', handleLogout);
  $('btn-open-change-pass').addEventListener('click', openChangePassModal);
  $('close-change-pass').addEventListener('click', closeChangePassModal);
  $('cancel-change-pass').addEventListener('click', closeChangePassModal);
  $('change-pass-form').addEventListener('submit', handleChangePassword);

  const handleOpenUsers = async () => {
    if (state.user?.role !== 'admin') return;
    openDrawer('users-drawer');
    await loadCollaborators();
  };
  $('nav-users').addEventListener('click', handleOpenUsers);
  $('btn-open-users-pill')?.addEventListener('click', handleOpenUsers);
  $('btn-refresh-users').addEventListener('click', loadCollaborators);
  $('btn-open-create-user').addEventListener('click', openCreateUserModal);
  $('close-create-user').addEventListener('click', closeCreateUserModal);
  $('cancel-create-user').addEventListener('click', closeCreateUserModal);
  $('create-user-form').addEventListener('submit', handleCreateUser);

  $('collaborators-list').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-user-action]');
    if (!btn) return;
    const tr = btn.closest('tr');
    if (!tr) return;
    const userId = Number(tr.dataset.userId);
    const username = tr.dataset.username;
    const status = tr.dataset.status;
    const action = btn.dataset.userAction;

    if (action === 'reset-pass') {
      openAdminResetPassModal(userId, username);
    } else if (action === 'toggle-status') {
      handleToggleUserStatus(userId, status);
    } else if (action === 'delete-user') {
      handleDeleteUser(userId, username);
    }
  });

  $('close-arp').addEventListener('click', closeAdminResetPassModal);
  $('cancel-arp').addEventListener('click', closeAdminResetPassModal);
  $('arp-form').addEventListener('submit', handleAdminResetPass);

  updateEditor();
  renderOutput();
  init();
})();
