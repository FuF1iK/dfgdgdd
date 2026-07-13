require('dotenv').config();
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const crypto = require('crypto');

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const watches = new Map();

const MAX_COL_WIDTH  = 12;
const MAX_LINE_WIDTH = 52;
const MAX_DESC_LEN   = 3800;

const fetchFn = globalThis.fetch ?? require('node-fetch');

// ---------- Проверка прав по ролям ----------

function hasPermission(interaction) {
  const allowedRoles = (process.env.ALLOWED_ROLE_IDS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (allowedRoles.length === 0) return true;
  if (!interaction.member) return false;
  return interaction.member.roles.cache.some(r => allowedRoles.includes(r.id));
}

// ---------- Обход анти-DDoS защиты (react.su) ----------

// Кэш: хост -> { cookie, expires }
const cookieCache = new Map();

function computeReactCookie(html) {
  // Извлекаем три hex-значения из скрипта анти-DDoS
  const hexValues = [...html.matchAll(/toNumbers\("([0-9a-f]{32})"\)/g)].map(m => m[1]);
  if (hexValues.length < 3) return null;
  const [keyHex, ivHex, ctHex] = hexValues;
  const key  = Buffer.from(keyHex, 'hex');
  const iv   = Buffer.from(ivHex, 'hex');
  const ct   = Buffer.from(ctHex, 'hex');
  try {
    const dec = crypto.createDecipheriv('aes-128-cbc', key, iv);
    dec.setAutoPadding(false);
    return Buffer.concat([dec.update(ct), dec.final()]).toString('hex');
  } catch (e) {
    return null;
  }
}

async function fetchWithAntiDDOS(url) {
  const host = new URL(url).hostname;
  const baseHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'ru-RU,ru;q=0.9',
  };

  // Попытка 1: если есть кэшированная cookie — используем её
  const cached = cookieCache.get(host);
  if (cached && cached.expires > Date.now()) {
    const res = await fetchFn(url, {
      headers: { ...baseHeaders, 'Cookie': `R3ACTLB=${cached.cookie}` }
    });
    const html = await res.text();
    if (!html.includes('Проверяем ваш браузер') && html.includes('__next_f')) {
      return html;
    }
  }

  // Попытка 2: загружаем страницу без cookie — должны получить анти-DDoS
  const res1 = await fetchFn(url, { headers: baseHeaders });
  const html1 = await res1.text();

  if (html1.includes('toNumbers') && html1.includes('R3ACTLB')) {
    // Вычисляем cookie через AES расшифровку
    const cookieVal = computeReactCookie(html1);
    if (!cookieVal) throw new Error('Не удалось вычислить anti-DDoS cookie');

    // Кэшируем на 12 часов
    cookieCache.set(host, { cookie: cookieVal, expires: Date.now() + 12 * 60 * 60 * 1000 });

    // Повторный запрос уже с cookie
    await new Promise(r => setTimeout(r, 2000)); // небольшая пауза как у браузера
    const res2 = await fetchFn(url, {
      headers: { ...baseHeaders, 'Cookie': `R3ACTLB=${cookieVal}` }
    });
    return await res2.text();
  }

  // Страница уже не антиДДОС — возвращаем как есть
  return html1;
}

// ---------- Парсинг данных из HTML ----------

function parseFamilyUrl(url) {
  const m = url.match(/\/family\/(\d+)/);
  const s = url.match(/[?&]server=([^&]+)/);
  if (!m) throw new Error('Не могу найти ID семьи в ссылке');
  return { familyId: m[1], server: s ? s[1] : 'ru7' };
}

function extractRosterFromHtml(html) {
  // Данные встроены в Next.js RSC payload: "roster":[{...}]
  const match = html.match(/"roster":\[(\{.+?\}(?:,\{.+?\})*)\]/);
  if (!match) throw new Error('Список игроков не найден на странице');
  return JSON.parse('[' + match[1] + ']');
}

async function fetchFamilyData(familyId, server) {
  const url  = `https://fletcher-wiki.com/players-family-stats/family/${familyId}?server=${server}`;
  const html = await fetchWithAntiDDOS(url);
  if (!html.includes('__next_f') && !html.includes('roster')) {
    throw new Error('Страница не загрузилась корректно. Попробуйте позже.');
  }
  const roster = extractRosterFromHtml(html);
  return roster;
}

// ---------- Форматирование таблицы ----------

function formatTable(rows, headerRowCount = 0) {
  if (!rows || rows.length === 0) return null;
  const clip = (text, max) => String(text || '').replace(/`/g, "'").slice(0, max);
  const colCount  = Math.max(...rows.map(r => r.length));
  const colWidths = Array(colCount).fill(0);
  for (const row of rows) {
    row.forEach((cell, i) => {
      colWidths[i] = Math.max(colWidths[i], clip(cell, MAX_COL_WIDTH).length);
    });
  }
  const sepW  = (colCount - 1) * 3;
  const total = colWidths.reduce((a, b) => a + b, 0);
  if (total + sepW > MAX_LINE_WIDTH) {
    const budget = MAX_LINE_WIDTH - sepW;
    const scale  = budget / total;
    for (let i = 0; i < colWidths.length; i++) {
      colWidths[i] = Math.max(i === 0 ? 2 : 1, Math.floor(colWidths[i] * scale));
    }
  }
  const lines = rows.map(row =>
    row.map((cell, i) => clip(cell, colWidths[i]).padEnd(colWidths[i] ?? 0)).join(' | ')
  );
  if (headerRowCount > 0 && lines.length > headerRowCount) {
    const sep = colWidths.map(w => '-'.repeat(w)).join('-+-');
    lines.splice(headerRowCount, 0, sep);
  }
  return lines.join('\n');
}

function buildTableEmbeds(url, allRows, title, footerText) {
  const header = allRows.slice(0, 1);
  const data   = allRows.slice(1);
  const chunks = [];
  let cur = [];
  for (const row of data) {
    const candidate = [...header, ...cur, row];
    const text = formatTable(candidate, 1);
    if (text && ('```\n' + text + '\n```').length > MAX_DESC_LEN && cur.length > 0) {
      chunks.push([...header, ...cur]);
      cur = [row];
    } else {
      cur.push(row);
    }
  }
  if (cur.length > 0) chunks.push([...header, ...cur]);
  return chunks.map((chunk, i) =>
    new EmbedBuilder()
      .setTitle(chunks.length > 1 ? `${title} (${i + 1}/${chunks.length})` : title)
      .setURL(url)
      .setDescription('```\n' + formatTable(chunk, 1) + '\n```')
      .setFooter({ text: i === chunks.length - 1 ? footerText : '\u200b' })
      .setTimestamp()
  );
}

async function buildFamilyEmbeds(url, familyId, server, period, intervalSec) {
  const roster = await fetchFamilyData(familyId, server);
  if (!Array.isArray(roster) || roster.length === 0) throw new Error('Пустой список игроков');

  const headers = ['#', 'Игрок', 'Ср.урон', 'Общ.урон', 'Убийств', 'Каптов'];
  const rows = roster.map((p, i) => [
    String(i + 1),
    String(p.name || ''),
    String(p.avgDamage   ?? 0),
    String(p.totalDamage ?? 0),
    String(p.totalKills  ?? 0),
    String(p.captsPlayed ?? 0),
  ]);

  const periodLabel = period === 'week' ? 'Неделя' : period === 'month' ? 'Месяц' : 'Сезон';
  return buildTableEmbeds(
    url,
    [headers, ...rows],
    `📊 Статистика семьи — ${periodLabel}`,
    `Обновляется каждые ${intervalSec} сек. • игроков: ${roster.length}`
  );
}

// ---------- Обновление по таймеру ----------

async function updateWatch(watchId) {
  const watch = watches.get(watchId);
  if (!watch) return;
  try {
    const channel = await client.channels.fetch(watch.channelId);
    const embeds  = await buildFamilyEmbeds(watch.url, watch.familyId, watch.server, watch.period, watch.intervalMs / 1000);
    for (let i = 0; i < embeds.length; i++) {
      if (i < watch.messageIds.length) {
        const msg = await channel.messages.fetch(watch.messageIds[i]);
        await msg.edit({ embeds: [embeds[i]] });
      } else {
        const msg = await channel.send({ embeds: [embeds[i]] });
        watch.messageIds.push(msg.id);
      }
    }
  } catch (err) {
    console.error(`Ошибка обновления watch ${watchId}:`, err.message);
  }
}

// ---------- Команды ----------

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  if (!hasPermission(interaction)) {
    return interaction.reply({ content: 'У вас нет прав для использования этой команды.', ephemeral: true });
  }

  if (interaction.commandName === 'family') {
    const url         = interaction.options.getString('url');
    const period      = interaction.options.getString('period') ?? 'week';
    const intervalSec = interaction.options.getInteger('interval') ?? 60;

    if (intervalSec < 10) {
      return interaction.reply({ content: 'Минимальный интервал — 10 секунд.', ephemeral: true });
    }

    let familyId, server;
    try {
      ({ familyId, server } = parseFamilyUrl(url));
    } catch (e) {
      return interaction.reply({ content: e.message, ephemeral: true });
    }

    await interaction.deferReply();

    try {
      const embeds = await buildFamilyEmbeds(url, familyId, server, period, intervalSec);
      const first  = await interaction.editReply({ embeds: [embeds[0]] });
      const messageIds = [first.id];
      for (let i = 1; i < embeds.length; i++) {
        const msg = await interaction.channel.send({ embeds: [embeds[i]] });
        messageIds.push(msg.id);
      }
      const intervalMs = intervalSec * 1000;
      const timer = setInterval(() => updateWatch(first.id), intervalMs);
      watches.set(first.id, { url, familyId, server, period, intervalMs, channelId: first.channelId, messageIds, timer });
    } catch (err) {
      console.error(err);
      await interaction.editReply(`Ошибка: ${err.message}`);
    }
  }

  if (interaction.commandName === 'unwatch') {
    const messageId = interaction.options.getString('message_id');
    const watch = watches.get(messageId);
    if (!watch) return interaction.reply({ content: 'Не нахожу такое наблюдение.', ephemeral: true });
    clearInterval(watch.timer);
    watches.delete(messageId);
    await interaction.reply({ content: 'Обновление остановлено.', ephemeral: true });
  }

  if (interaction.commandName === 'listwatches') {
    if (watches.size === 0) return interaction.reply({ content: 'Нет активных наблюдений.', ephemeral: true });
    const lines = [...watches.entries()].map(
      ([id, w]) => `• \`${id}\` — семья ${w.familyId} (${w.server}, ${w.period}, каждые ${w.intervalMs / 1000} сек.)`
    );
    await interaction.reply({ content: lines.join('\n'), ephemeral: true });
  }
});

client.once('clientReady', () => console.log(`Бот запущен как ${client.user.tag}`));

process.on('SIGINT', async () => {
  for (const w of watches.values()) clearInterval(w.timer);
  process.exit(0);
});

client.login(process.env.DISCORD_TOKEN);
