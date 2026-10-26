'use strict';

const byId = (id) => document.getElementById(id);
const value = (id) => byId(id).value;
let lastResult = null;
let textCipher = null;
let cbcCipher = null;
let vectors = [];

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

async function api(path, data) {
  const response = await fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `请求失败（${response.status}）`);
  return result;
}

function errorMessage(target, error) {
  target.replaceChildren(element('p', error.message, 'error'));
}

function showValue(target, label, text, small = false) {
  target.append(element('p', label, 'result-label'),
    element('p', text, `result-value${small ? ' small' : ''}`));
}

function table(headers, rows, caption) {
  const wrapper = element('div', undefined, 'table-wrap');
  const grid = element('table');
  const title = element('caption', caption);
  grid.append(title);
  const head = element('thead');
  const heading = element('tr');
  headers.forEach((text) => {
    const cell = element('th', text);
    cell.scope = 'col';
    heading.append(cell);
  });
  head.append(heading);
  grid.append(head);
  const body = element('tbody');
  rows.forEach(({ cells, className }) => {
    const row = element('tr', undefined, className);
    cells.forEach((text) => row.append(element('td', String(text))));
    body.append(row);
  });
  grid.append(body);
  wrapper.append(grid);
  return wrapper;
}

function bindForm(formId, resultId, buildRequest, render) {
  const form = byId(formId);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const target = byId(resultId);
    const buttons = [...form.querySelectorAll('button')];
    buttons.forEach((button) => { button.disabled = true; });
    form.setAttribute('aria-busy', 'true');
    if (formId === 'basic-form') {
      byId('trace').replaceChildren(element('p', '本次计算完成后显示轮变换。', 'hint'));
      byId('state-matrix').replaceChildren(...['?', '?', '?', '?'].map((nibble) => element('span', nibble)));
      byId('matrix-caption').textContent = '等待本次计算结果';
      byId('round-keys').replaceChildren(element('p', '等待本次密钥扩展'));
    }
    if (formId === 'tamper-form') {
      byId('tamper-result').replaceChildren(element('p', '本次篡改完成后显示分组对比。', 'hint'));
    }
    target.replaceChildren(element('p', formId === 'mitm-form' ? '正在遍历两侧完整的 65,536 个密钥…' : '正在计算…', 'hint'));
    lastResult = null;
    byId('download-result').disabled = true;
    try {
      const request = buildRequest(event.submitter?.value || 'encrypt');
      const result = await api(request.path, request.data);
      target.replaceChildren();
      render(result, target, request.data);
      // Exports contain outputs only. Plaintext/key input fields are not silently persisted.
      lastResult = { experiment: formId.replace('-form', ''), result };
      byId('download-result').disabled = false;
    } catch (error) {
      errorMessage(target, error);
    } finally {
      buttons.forEach((button) => { button.disabled = false; });
      form.removeAttribute('aria-busy');
    }
  });
}

const tabs = [...document.querySelectorAll('[role="tab"]')];
function selectPanel(tab, focus = false) {
  tabs.forEach((candidate) => {
    const selected = candidate === tab;
    candidate.setAttribute('aria-selected', String(selected));
    candidate.tabIndex = selected ? 0 : -1;
    byId(`panel-${candidate.dataset.panel}`).hidden = !selected;
  });
  if (focus) tab.focus();
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectPanel(tab));
  tab.addEventListener('keydown', (event) => {
    let next = index;
    if (['ArrowDown', 'ArrowRight'].includes(event.key)) next = (index + 1) % tabs.length;
    else if (['ArrowUp', 'ArrowLeft'].includes(event.key)) next = (index + tabs.length - 1) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else return;
    event.preventDefault();
    selectPanel(tabs[next], true);
  });
});

function showMatrix(step) {
  byId('state-matrix').replaceChildren(...step.matrix.flat().map((nibble) => element('span', nibble)));
  byId('matrix-caption').textContent = `${step.step} · ${step.value}`;
}

bindForm('basic-form', 'basic-result', (action) => ({ path: '/api/block', data: {
  action, format: value('basic-format'), data: value('basic-data'), key: value('basic-key')
}}), (result, target, request) => {
  showValue(target, request.action === 'encrypt' ? '密文 · 二进制' : '明文 · 二进制', result.binary);
  showValue(target, '十六进制', result.hex, true);
  byId('round-keys').replaceChildren(...result.round_keys.map((key, index) => {
    const item = element('div', `K${index}`);
    item.append(element('code', key));
    return item;
  }));
  byId('trace').replaceChildren(...result.trace.map((step, index) => {
    const button = element('button', `${index}. ${step.step}`, 'trace-step');
    button.type = 'button';
    button.setAttribute('aria-pressed', String(index === result.trace.length - 1));
    button.append(element('code', step.value));
    button.addEventListener('click', () => {
      byId('trace').querySelectorAll('button').forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
      showMatrix(step);
    });
    return button;
  }));
  showMatrix(result.trace.at(-1));
});

let basicFormat = 'bin';
let multipleFormat = 'hex';
function convertInput(id, from, to) {
  const compact = value(id).replace(/\s/g, '');
  const width = from === 'bin' ? 16 : 4;
  const pattern = from === 'bin' ? /^[01]+$/ : /^[0-9a-f]+$/i;
  if (!compact || compact.length % width || !pattern.test(compact)) return;
  const words = [];
  for (let i = 0; i < compact.length; i += width) {
    const number = parseInt(compact.slice(i, i + width), from === 'bin' ? 2 : 16);
    words.push(number.toString(to === 'bin' ? 2 : 16).padStart(to === 'bin' ? 16 : 4, '0').toUpperCase());
  }
  byId(id).value = words.join('');
}
byId('basic-format').addEventListener('change', () => {
  ['basic-data', 'basic-key'].forEach((id) => convertInput(id, basicFormat, value('basic-format')));
  basicFormat = value('basic-format');
});
byId('basic-example').addEventListener('click', () => {
  byId('basic-data').value = value('basic-format') === 'bin' ? '1101011100101000' : 'D728';
  byId('basic-key').value = value('basic-format') === 'bin' ? '0100101011110101' : '4AF5';
});

async function loadVectors() {
  const response = await fetch('/vectors.json');
  if (!response.ok) throw new Error('测试向量载入失败');
  vectors = await response.json();
  byId('cross-vectors').value = JSON.stringify(vectors, null, 2);
}
byId('cross-example').addEventListener('click', () => {
  byId('cross-vectors').value = JSON.stringify(vectors, null, 2);
});
bindForm('cross-form', 'cross-result', () => {
  let parsed;
  try { parsed = JSON.parse(value('cross-vectors')); }
  catch { throw new Error('测试向量不是有效 JSON，请检查引号、逗号与括号'); }
  return { path: '/api/cross', data: { vectors: parsed } };
}, (result, target) => {
  target.append(element('p', `${result.passed} / ${result.total} 组加解密一致`, result.passed === result.total ? 'success' : 'error'));
  target.append(table(['明文', '密钥', '预期密文', '实际密文', '还原明文', '结果'], result.rows.map((row) => ({
    cells: [row.plaintext, row.key, row.expected, row.actual, row.restored, row.passed ? '通过' : '不一致'],
    className: row.passed ? 'passed' : 'failed'
  })), '测试向量逐项对照'));
});

function renderBytes(result, target, request) {
  if (request.action === 'decrypt') showValue(target, '还原的 ASCII 明文', result.text || '（空字符串）', true);
  showValue(target, request.action === 'decrypt' ? '明文字节 · HEX' : '密文 · HEX', result.hex || '（空）', true);
  if (request.action === 'encrypt') {
    target.append(element('p', `${result.byte_length} 字节 / ${result.blocks.length} 个分组`, 'hint'));
    target.append(element('p', '字节字符的 JSON 转义表示', 'result-label'), element('pre', result.escaped));
  }
  if (result.iv) showValue(target, '共享的初始向量 IV', result.iv, true);
}
bindForm('text-form', 'text-result', (action) => {
  byId('text-use').hidden = true;
  return { path: '/api/text', data: { action, key: value('text-key'), data: value('text-data'), representation: value('text-representation') }};
}, (result, target, request) => {
  renderBytes(result, target, request);
  textCipher = request.action === 'encrypt' ? result : null;
  byId('text-use').hidden = !textCipher;
});
byId('text-use').addEventListener('click', () => {
  byId('text-data').value = value('text-representation') === 'escaped' ? textCipher.escaped : textCipher.hex;
  byId('text-data').focus();
});

function multipleFormula() {
  const mode = value('multiple-mode');
  byId('multiple-formula').textContent = mode === 'double' ? 'C = E(K₂, E(K₁, P))' :
    mode === 'triple32' ? 'C = E(K₁, D(K₂, E(K₁, P)))' : 'C = E(K₃, D(K₂, E(K₁, P)))';
}
byId('multiple-mode').addEventListener('change', () => {
  multipleFormula();
  const width = value('multiple-format') === 'bin' ? 16 : 4;
  let key = value('multiple-key').replace(/\s/g, '');
  if (value('multiple-mode') === 'triple48' && key.length === width * 2) key += width === 4 ? '5678' : '0101011001111000';
  else if (value('multiple-mode') !== 'triple48' && key.length === width * 3) key = key.slice(0, width * 2);
  byId('multiple-key').value = key;
});
byId('multiple-format').addEventListener('change', () => {
  ['multiple-data', 'multiple-key'].forEach((id) => convertInput(id, multipleFormat, value('multiple-format')));
  multipleFormat = value('multiple-format');
});
bindForm('multiple-form', 'multiple-result', (action) => ({ path: '/api/multiple', data: {
  action, mode: value('multiple-mode'), format: value('multiple-format'), data: value('multiple-data'), key: value('multiple-key')
}}), (result, target, request) => {
  showValue(target, request.action === 'encrypt' ? '密文 · HEX' : '明文 · HEX', result.hex);
  showValue(target, '二进制', result.binary, true);
});

byId('mitm-demo').addEventListener('click', async () => {
  const button = byId('mitm-demo');
  button.disabled = true;
  try {
    const key = value('multiple-key').replace(/\s/g, '');
    const width = value('multiple-format') === 'bin' ? 32 : 8;
    const result = await api('/api/pairs', { key: key.slice(0, width), format: value('multiple-format') });
    byId('mitm-pairs').value = result.pairs.map((pair) => `${pair.plaintext} ${pair.ciphertext}`).join('\n');
    byId('mitm-result').replaceChildren(element('p', '已生成 3 组双重 EE 加密明密文对。点击搜索开始攻击。', 'hint'));
  } catch (error) { errorMessage(byId('mitm-result'), error); }
  finally { button.disabled = false; }
});
bindForm('mitm-form', 'mitm-result', () => {
  const lines = value('mitm-pairs').trim().split(/\n/).filter((line) => line.trim());
  const pairs = lines.map((line) => {
    const pair = line.trim().split(/\s+/);
    if (pair.length !== 2) throw new Error('每行需要一个 4 位明文和一个 4 位密文，以空格分隔');
    return { plaintext: pair[0], ciphertext: pair[1] };
  });
  return { path: '/api/mitm', data: { pairs } };
}, (result, target) => {
  showValue(target, '符合全部已知明密文对的候选密钥数', String(result.candidate_count));
  target.append(element('p', `两侧各搜索 ${result.searched_per_side.toLocaleString()} 个密钥；首组匹配 ${result.first_pair_matches.toLocaleString()} 对；耗时 ${result.elapsed_seconds} 秒。`, 'hint'));
  if (result.keys.length) target.append(element('pre', result.keys.slice(0, 100).join('\n')));
  const message = result.candidate_count === 1 ? '当前仅有一个候选，可用额外明密文对继续确认。' :
    result.candidate_count === 0 ? '未找到匹配密钥。请核对数据是否来自相同密钥的双重 EE 加密。' :
    '存在多个候选，请增加不同明文的已知对以排除歧义。';
  target.append(element('p', message, 'hint'));
  if (result.keys.length > 100) target.append(element('p', '界面显示前 100 个候选，下载本次结果可获得全部候选。', 'hint'));
});

byId('cbc-random').addEventListener('click', async () => {
  try { byId('cbc-iv').value = (await api('/api/iv', {})).iv; }
  catch (error) { errorMessage(byId('cbc-result'), error); }
});
bindForm('cbc-form', 'cbc-result', (action) => {
  byId('cbc-use').hidden = true;
  return { path: '/api/cbc', data: { action, key: value('cbc-key'), iv: value('cbc-iv'), data: value('cbc-data') }};
}, (result, target, request) => {
  renderBytes(result, target, request);
  byId('cbc-iv').value = result.iv;
  cbcCipher = request.action === 'encrypt' ? result : null;
  byId('cbc-use').hidden = !cbcCipher;
  if (cbcCipher) byId('tamper-data').value = cbcCipher.hex;
});
byId('cbc-use').addEventListener('click', () => {
  byId('cbc-data').value = cbcCipher.hex;
  byId('tamper-data').value = cbcCipher.hex;
  byId('cbc-iv').value = cbcCipher.iv;
  byId('cbc-data').focus();
});
bindForm('tamper-form', 'tamper-status', () => ({ path: '/api/tamper', data: {
  key: value('cbc-key'), iv: value('cbc-iv'), data: value('tamper-data'), index: Number(value('tamper-index')),
  change: value('tamper-change'), operation: value('tamper-operation')
}}), (result, target) => {
  showValue(target, '篡改后的密文 · HEX', result.modified_cipher, true);
  target.append(element('p', `填充${result.padding_valid ? '仍然有效' : '已损坏'}。填充状态不能作为完整性认证。`, 'hint'));
  byId('tamper-result').replaceChildren(table(['分组', '原始解密', '篡改后解密', '逐位异或', '变化'], result.blocks.map((block) => ({
    cells: [block.index, `${block.before} ${block.before_text}`, `${block.after} ${block.after_text}`, block.xor, block.changed ? '已改变' : '不变'],
    className: block.changed ? 'changed' : ''
  })), '解密后的原始字节，包含 PKCS#7 填充'));
});

byId('download-result').addEventListener('click', () => {
  if (!lastResult) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' }));
  const link = element('a');
  link.href = url;
  link.download = `saes-${lastResult.experiment}-result.json`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

loadVectors().catch((error) => errorMessage(byId('cross-result'), error));
