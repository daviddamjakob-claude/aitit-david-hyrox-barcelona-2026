// aitit-training-os — Cloudflare Worker backing the multi-athlete Training OS.
//
// Athlete-facing routes (require header X-Session-Token, issued by /auth/login):
//   POST /auth/login {username,password} -> {token,athleteId,displayName}
//   POST /auth/logout                    -> {ok:true}          (deletes the session row)
//   GET  /me                             -> {displayName, programs:[{id,name}]}
//   GET  /program/:id/config             -> {phases:[...], activityTypes:[...]}
//   GET  /program/:id/state              -> stored JSON blob (or null)
//   POST /program/:id/state              -> stores the request body as the JSON blob
//
// Admin routes (no auth check — protected only by the URL being unlisted, by design):
//   GET  /admin/athletes                 POST /admin/athletes {username,password,displayName,programIds}
//   PUT  /admin/athletes/:id/programs     {programIds}
//   GET  /admin/programs                 POST /admin/programs {name}
//   GET  /admin/programs/:id
//   POST /admin/programs/:id/phases       {name,startDate,endDate}
//   PUT  /admin/programs/:id/phases/:phaseId   {name,startDate,endDate}
//   DELETE /admin/programs/:id/phases/:phaseId
//   PUT  /admin/programs/:id/activity-types/:key   {label,infoText}

const ALLOWED_ORIGIN = 'https://daviddamjakob-claude.github.io';

const DEFAULT_ACTIVITY_TYPES = [
  { key: 'zone2', label: 'Zone 2 Cardio', infoText: 'Longer, aerobic effort — which means that you avoid the high intensity zones. Steered by HR, keep the average at 65–75% of your true max (approx. 220 - age). This should be a pace at which you could still have a conversation. Ideally aim for 60+min, especially for your main Zone 2 session in a week. Possible to alternate runs with cycling or even row/ski erg.' },
  { key: 'runIntervals', label: 'Run Intervals', infoText: 'Intense efforts separated by short breaks. Common intervals are 400m (10-20x), 1km or 1.2km (4-8x), 2km (3-5x). Breaks are 1-2min at moderate walking pace. Total work session length varies between 30-60min, ideally with an additional warm-up and cool-down at relaxed pace (~1km each).' },
  { key: 'exerciseIntervals', label: 'Hybrid Intervals', infoText: 'Intense efforts separated by short breaks. Typically with a mix of row erg, ski erg and running sets, commonly mixed with burpee jumps, lunges and wall balls. Shorten the breaks over time — races are won on tired legs and in the transitions between runs and exercises. Total work session length varies between 45-60min.' },
  { key: 'strength', label: 'Strength', infoText: 'Preference-led. Can but doesn’t need to have a Hyrox focus (lower-body and leg strength, grip strength, sled push & pull work).' },
  { key: 'mobility', label: 'Mobility & Recovery', infoText: 'Preference-led. Effective options include but are not limited to yoga, stretching, mobility, massage or sauna.' },
];

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
  };
}
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { ...cors, 'Content-Type': 'application/json' } });
}
async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

// ---------------- password hashing (PBKDF2, Web Crypto) ----------------
async function pbkdf2(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  return Buffer.from(bits).toString('base64');
}
async function hashNewPassword(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  return { hash: await pbkdf2(password, saltBytes), salt: Buffer.from(saltBytes).toString('base64') };
}
async function verifyPassword(password, saltB64, hashB64) {
  return (await pbkdf2(password, Buffer.from(saltB64, 'base64'))) === hashB64;
}

// ---------------- session helpers ----------------
async function requireAthlete(request, env) {
  const token = request.headers.get('X-Session-Token');
  if (!token) return null;
  const row = await env.DB.prepare('SELECT athlete_id FROM sessions WHERE token = ?').bind(token).first();
  return row ? row.athlete_id : null;
}
async function athleteHasProgram(env, athleteId, programId) {
  const row = await env.DB.prepare('SELECT 1 FROM athlete_programs WHERE athlete_id = ? AND program_id = ?').bind(athleteId, programId).first();
  return !!row;
}

// ---------------- route handlers ----------------
async function handleLogin(request, env, cors) {
  const body = await readJson(request);
  if (!body || !body.username || !body.password) return json({ error: 'username and password required' }, 400, cors);
  const athlete = await env.DB.prepare('SELECT id, password_hash, salt, display_name FROM athletes WHERE username = ?').bind(body.username).first();
  if (!athlete || !(await verifyPassword(body.password, athlete.salt, athlete.password_hash))) {
    return json({ error: 'Invalid username or password' }, 401, cors);
  }
  const token = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO sessions (token, athlete_id) VALUES (?, ?)').bind(token, athlete.id).run();
  return json({ token, athleteId: athlete.id, displayName: athlete.display_name }, 200, cors);
}
async function handleLogout(request, env, cors) {
  const token = request.headers.get('X-Session-Token');
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  return json({ ok: true }, 200, cors);
}
async function handleMe(request, env, cors) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  const athlete = await env.DB.prepare('SELECT display_name FROM athletes WHERE id = ?').bind(athleteId).first();
  const programs = await env.DB.prepare(
    'SELECT p.id, p.name FROM programs p JOIN athlete_programs ap ON ap.program_id = p.id WHERE ap.athlete_id = ? ORDER BY p.id'
  ).bind(athleteId).all();
  return json({ displayName: athlete.display_name, programs: programs.results }, 200, cors);
}
async function handleProgramConfig(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  const phases = await env.DB.prepare('SELECT id, name, start_date AS startDate, end_date AS endDate FROM phases WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  const activityTypes = await env.DB.prepare('SELECT key, label, info_text AS infoText FROM activity_types WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  return json({ phases: phases.results, activityTypes: activityTypes.results }, 200, cors);
}
async function handleStateGet(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  const row = await env.DB.prepare('SELECT data FROM program_state WHERE athlete_id = ? AND program_id = ?').bind(athleteId, programId).first();
  return new Response(row ? row.data : 'null', { headers: { ...cors, 'Content-Type': 'application/json' } });
}
async function handleStatePost(request, env, cors, programId) {
  const athleteId = await requireAthlete(request, env);
  if (!athleteId) return json({ error: 'Unauthorized' }, 401, cors);
  if (!(await athleteHasProgram(env, athleteId, programId))) return json({ error: 'Forbidden' }, 403, cors);
  const body = await request.text();
  try { JSON.parse(body); } catch { return json({ error: 'Invalid JSON' }, 400, cors); }
  await env.DB.prepare(
    'INSERT INTO program_state (athlete_id, program_id, data, updated_at) VALUES (?, ?, ?, datetime(\'now\')) ' +
    'ON CONFLICT(athlete_id, program_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
  ).bind(athleteId, programId, body).run();
  return json({ ok: true }, 200, cors);
}

// ---------------- admin handlers (no auth, by design) ----------------
async function adminListAthletes(env, cors) {
  const athletes = await env.DB.prepare('SELECT id, username, display_name AS displayName FROM athletes ORDER BY id').all();
  const links = await env.DB.prepare(
    'SELECT ap.athlete_id AS athleteId, p.id AS programId, p.name FROM athlete_programs ap JOIN programs p ON p.id = ap.program_id'
  ).all();
  const byAthlete = {};
  for (const l of links.results) (byAthlete[l.athleteId] ||= []).push({ id: l.programId, name: l.name });
  return json(athletes.results.map(a => ({ ...a, programs: byAthlete[a.id] || [] })), 200, cors);
}
async function adminCreateAthlete(request, env, cors) {
  const body = await readJson(request);
  if (!body || !body.username || !body.password || !body.displayName) return json({ error: 'username, password, displayName required' }, 400, cors);
  const { hash, salt } = await hashNewPassword(body.password);
  const result = await env.DB.prepare('INSERT INTO athletes (username, password_hash, salt, display_name) VALUES (?, ?, ?, ?)')
    .bind(body.username, hash, salt, body.displayName).run();
  const athleteId = result.meta.last_row_id;
  for (const programId of (body.programIds || [])) {
    await env.DB.prepare('INSERT INTO athlete_programs (athlete_id, program_id) VALUES (?, ?)').bind(athleteId, programId).run();
  }
  return json({ id: athleteId }, 201, cors);
}
async function adminUpdateAthletePrograms(request, env, cors, athleteId) {
  const body = await readJson(request);
  if (!body || !Array.isArray(body.programIds)) return json({ error: 'programIds array required' }, 400, cors);
  await env.DB.prepare('DELETE FROM athlete_programs WHERE athlete_id = ?').bind(athleteId).run();
  for (const programId of body.programIds) {
    await env.DB.prepare('INSERT INTO athlete_programs (athlete_id, program_id) VALUES (?, ?)').bind(athleteId, programId).run();
  }
  return json({ ok: true }, 200, cors);
}
async function adminListPrograms(env, cors) {
  const programs = await env.DB.prepare('SELECT id, name FROM programs ORDER BY id').all();
  return json(programs.results, 200, cors);
}
async function adminCreateProgram(request, env, cors) {
  const body = await readJson(request);
  if (!body || !body.name) return json({ error: 'name required' }, 400, cors);
  const result = await env.DB.prepare('INSERT INTO programs (name) VALUES (?)').bind(body.name).run();
  const programId = result.meta.last_row_id;
  let order = 0;
  for (const a of DEFAULT_ACTIVITY_TYPES) {
    await env.DB.prepare('INSERT INTO activity_types (program_id, key, label, info_text, sort_order) VALUES (?, ?, ?, ?, ?)')
      .bind(programId, a.key, a.label, a.infoText, order++).run();
  }
  return json({ id: programId }, 201, cors);
}
async function adminGetProgram(env, cors, programId) {
  const program = await env.DB.prepare('SELECT id, name FROM programs WHERE id = ?').bind(programId).first();
  if (!program) return json({ error: 'Not found' }, 404, cors);
  const phases = await env.DB.prepare('SELECT id, name, start_date AS startDate, end_date AS endDate FROM phases WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  const activityTypes = await env.DB.prepare('SELECT key, label, info_text AS infoText FROM activity_types WHERE program_id = ? ORDER BY sort_order').bind(programId).all();
  return json({ ...program, phases: phases.results, activityTypes: activityTypes.results }, 200, cors);
}
async function adminCreatePhase(request, env, cors, programId) {
  const body = await readJson(request);
  if (!body || !body.name || !body.startDate || !body.endDate) return json({ error: 'name, startDate, endDate required' }, 400, cors);
  const maxOrder = await env.DB.prepare('SELECT COALESCE(MAX(sort_order), -1) AS m FROM phases WHERE program_id = ?').bind(programId).first();
  const result = await env.DB.prepare('INSERT INTO phases (program_id, name, start_date, end_date, sort_order) VALUES (?, ?, ?, ?, ?)')
    .bind(programId, body.name, body.startDate, body.endDate, maxOrder.m + 1).run();
  return json({ id: result.meta.last_row_id }, 201, cors);
}
async function adminUpdatePhase(request, env, cors, phaseId) {
  const body = await readJson(request);
  if (!body || !body.name || !body.startDate || !body.endDate) return json({ error: 'name, startDate, endDate required' }, 400, cors);
  await env.DB.prepare('UPDATE phases SET name = ?, start_date = ?, end_date = ? WHERE id = ?').bind(body.name, body.startDate, body.endDate, phaseId).run();
  return json({ ok: true }, 200, cors);
}
async function adminDeletePhase(env, cors, phaseId) {
  await env.DB.prepare('DELETE FROM phases WHERE id = ?').bind(phaseId).run();
  return json({ ok: true }, 200, cors);
}
async function adminUpdateActivityType(request, env, cors, programId, key) {
  const body = await readJson(request);
  if (!body || !body.label || !body.infoText) return json({ error: 'label, infoText required' }, 400, cors);
  await env.DB.prepare('UPDATE activity_types SET label = ?, info_text = ? WHERE program_id = ? AND key = ?')
    .bind(body.label, body.infoText, programId, key).run();
  return json({ ok: true }, 200, cors);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    const url = new URL(request.url);
    const seg = url.pathname.split('/').filter(Boolean);
    const method = request.method;

    try {
      if (method === 'POST' && seg[0] === 'auth' && seg[1] === 'login') return handleLogin(request, env, cors);
      if (method === 'POST' && seg[0] === 'auth' && seg[1] === 'logout') return handleLogout(request, env, cors);
      if (method === 'GET' && seg[0] === 'me') return handleMe(request, env, cors);

      if (seg[0] === 'program' && seg[2] === 'config' && method === 'GET') return handleProgramConfig(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'state' && method === 'GET') return handleStateGet(request, env, cors, seg[1]);
      if (seg[0] === 'program' && seg[2] === 'state' && method === 'POST') return handleStatePost(request, env, cors, seg[1]);

      if (seg[0] === 'admin' && seg[1] === 'athletes' && !seg[2] && method === 'GET') return adminListAthletes(env, cors);
      if (seg[0] === 'admin' && seg[1] === 'athletes' && !seg[2] && method === 'POST') return adminCreateAthlete(request, env, cors);
      if (seg[0] === 'admin' && seg[1] === 'athletes' && seg[3] === 'programs' && method === 'PUT') return adminUpdateAthletePrograms(request, env, cors, seg[2]);

      if (seg[0] === 'admin' && seg[1] === 'programs' && !seg[2] && method === 'GET') return adminListPrograms(env, cors);
      if (seg[0] === 'admin' && seg[1] === 'programs' && !seg[2] && method === 'POST') return adminCreateProgram(request, env, cors);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[2] && !seg[3] && method === 'GET') return adminGetProgram(env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'phases' && !seg[4] && method === 'POST') return adminCreatePhase(request, env, cors, seg[2]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'phases' && seg[4] && method === 'PUT') return adminUpdatePhase(request, env, cors, seg[4]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'phases' && seg[4] && method === 'DELETE') return adminDeletePhase(env, cors, seg[4]);
      if (seg[0] === 'admin' && seg[1] === 'programs' && seg[3] === 'activity-types' && seg[4] && method === 'PUT') return adminUpdateActivityType(request, env, cors, seg[2], seg[4]);

      return json({ error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ error: String(err && err.message || err) }, 500, cors);
    }
  },
};
