/* =====================================================================
   Listado — servidor (Cloudflare Worker, rutas /api/*)
   La base D1 (binding DB) la crea Cloudflare sola al publicar (ver wrangler.jsonc).
   Configurar en Cloudflare (Worker > Settings > Variables and Secrets):
     - Secreto  ANTHROPIC_API_KEY   (clave de la IA)
     - Secreto  ADMIN_PASSWORD      (contraseña del administrador; opcional)
     - Variable ADMIN_USUARIO       (opcional, por defecto "adm")
     - Variable IA_MODELO           (opcional, por defecto claude-sonnet-5-5)
   Las tablas se crean solas la primera vez.
   ===================================================================== */

const ESQUEMA = [
  `CREATE TABLE IF NOT EXISTS usuarios (id TEXT PRIMARY KEY, nombre TEXT NOT NULL, usuario TEXT NOT NULL UNIQUE, pass TEXT NOT NULL, sal TEXT NOT NULL, rol TEXT, creado INTEGER)`,
  `CREATE TABLE IF NOT EXISTS sesiones (token TEXT PRIMARY KEY, usuario_id TEXT NOT NULL, expira INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS intentos (clave TEXT PRIMARY KEY, n INTEGER NOT NULL, hasta INTEGER NOT NULL)`,
  // Tabla 1: alumnos totales
  `CREATE TABLE IF NOT EXISTS alumnos (id TEXT PRIMARY KEY, apellido TEXT NOT NULL, nombre TEXT NOT NULL, curso TEXT NOT NULL, activo INTEGER NOT NULL DEFAULT 1, creado INTEGER)`,
  // Tabla 2: alumnos asistentes (un registro por alumno por día: P presente, T tarde, A ausente)
  `CREATE TABLE IF NOT EXISTS asistencias (id TEXT PRIMARY KEY, fecha TEXT NOT NULL, alumno_id TEXT NOT NULL, curso TEXT NOT NULL, estado TEXT NOT NULL, hora TEXT, usuario_id TEXT, ts INTEGER, UNIQUE(fecha, alumno_id))`,
  `CREATE INDEX IF NOT EXISTS ix_asis_fecha ON asistencias(fecha, curso)`,
  `CREATE INDEX IF NOT EXISTS ix_asis_alumno ON asistencias(alumno_id, fecha)`,
];
// Hash SHA-256 de la contraseña por defecto del admin (se usa solo si no está el secreto ADMIN_PASSWORD)
const ADMIN_HASH_DEFECTO = 'd64acc11a39defb2be2226e5f9074a89b156a8371079a88a1ab9d4fd06d6f955';
const DIAS_SESION = 30;

let tablasListas = false;
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'content-type, authorization',
  'access-control-allow-methods': 'POST, GET, OPTIONS',
};
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json; charset=utf-8', ...CORS } });
class Falla extends Error { constructor(m, s = 400) { super(m); this.s = s; } }
const id = () => crypto.randomUUID();
const ahora = () => Date.now();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha256 = async t => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)));
async function derivar(pass, sal) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(sal), iterations: 100000, hash: 'SHA-256' }, k, 256));
}
function iguales(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
const limpiarUsuario = s => String(s || '').trim().toLowerCase().replace(/\s+/g, '');
const texto = (s, max = 80) => String(s ?? '').trim().slice(0, max);
const cap = s => texto(s).toLowerCase().replace(/(^|\s|-|')\S/g, m => m.toUpperCase());
const curso = s => texto(s, 20).toUpperCase().replace(/\s+/g, ' ');
const FECHA = /^\d{4}-\d{2}-\d{2}$/, HORA = /^\d{2}:\d{2}$/;

/* ---------- control de intentos de ingreso (bloquea 15 min tras 8 fallas) ---------- */
async function revisarBloqueo(db, clave) {
  const r = await db.prepare('SELECT n, hasta FROM intentos WHERE clave=?').bind(clave).first();
  if (r && r.n >= 8 && r.hasta > ahora()) throw new Falla('Demasiados intentos. Probá de nuevo en 15 minutos.', 429);
}
async function sumarFalla(db, clave) {
  await db.prepare(`INSERT INTO intentos (clave,n,hasta) VALUES (?,1,?) ON CONFLICT(clave) DO UPDATE SET n=CASE WHEN hasta<? THEN 1 ELSE n+1 END, hasta=?`)
    .bind(clave, ahora() + 9e5, ahora(), ahora() + 9e5).run();
}
const limpiarFallas = (db, clave) => db.prepare('DELETE FROM intentos WHERE clave=?').bind(clave).run();

async function crearSesion(db, usuarioId) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  await db.prepare('INSERT INTO sesiones (token,usuario_id,expira) VALUES (?,?,?)').bind(token, usuarioId, ahora() + DIAS_SESION * 864e5).run();
  return token;
}
const adminUsuario = env => limpiarUsuario(env.ADMIN_USUARIO || 'adm');
const adminPublico = env => ({ id: '__admin', nombre: 'Administrador', usuario: adminUsuario(env), rol: 'admin' });
const publico = u => ({ id: u.id, nombre: u.nombre, usuario: u.usuario, rol: u.rol || null });

async function quienSoy(db, env, request) {
  const token = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const s = await db.prepare('SELECT usuario_id, expira FROM sesiones WHERE token=?').bind(token).first();
  if (!s || s.expira < ahora()) return null;
  if (s.usuario_id === '__admin') return { ...adminPublico(env), token };
  const u = await db.prepare('SELECT * FROM usuarios WHERE id=?').bind(s.usuario_id).first();
  return u ? { ...publico(u), token } : null;
}
function exigir(yo, ...roles) {
  if (!yo) throw new Falla('Tenés que ingresar de nuevo', 401);
  if (!yo.rol) throw new Falla('Tu cuenta todavía no tiene rol asignado', 403);
  if (roles.length && !roles.includes(yo.rol)) throw new Falla('No tenés permiso para esto', 403);
}

/* ============================ ACCIONES ============================ */
const acciones = {
  async salud({ env }) { return { ok: true, base: true, ia: !!env.ANTHROPIC_API_KEY, adminSecreto: !!env.ADMIN_PASSWORD }; },

  async registro({ db, env, d }) {
    const nombre = texto(d.nombre, 60), usuario = limpiarUsuario(d.usuario), pass = String(d.pass || '');
    if (!nombre || !usuario || pass.length < 4) throw new Falla('Completá todo (contraseña de 4+ caracteres)');
    if (!/^[a-z0-9._-]{3,30}$/.test(usuario)) throw new Falla('El usuario debe tener 3 a 30 letras o números, sin espacios ni acentos');
    if (usuario === adminUsuario(env)) throw new Falla('Ese usuario ya existe');
    const sal = hex(crypto.getRandomValues(new Uint8Array(16)));
    const u = { id: id(), nombre, usuario, pass: await derivar(pass, sal), sal, rol: null };
    try {
      await db.prepare('INSERT INTO usuarios (id,nombre,usuario,pass,sal,rol,creado) VALUES (?,?,?,?,?,?,?)').bind(u.id, u.nombre, u.usuario, u.pass, u.sal, null, ahora()).run();
    } catch { throw new Falla('Ese usuario ya existe'); }
    return { token: await crearSesion(db, u.id), usuario: publico(u) };
  },

  async login({ db, env, d }) {
    const usuario = limpiarUsuario(d.usuario), pass = String(d.pass || '');
    const clave = 'u:' + usuario;
    await revisarBloqueo(db, clave);
    if (usuario === adminUsuario(env)) {
      const ok = env.ADMIN_PASSWORD ? iguales(pass, env.ADMIN_PASSWORD) : iguales(await sha256(pass), ADMIN_HASH_DEFECTO);
      if (!ok) { await sumarFalla(db, clave); throw new Falla('Usuario o contraseña incorrectos', 401); }
      await limpiarFallas(db, clave);
      return { token: await crearSesion(db, '__admin'), usuario: adminPublico(env) };
    }
    const u = await db.prepare('SELECT * FROM usuarios WHERE usuario=?').bind(usuario).first();
    if (!u || !iguales(await derivar(pass, u.sal), u.pass)) { await sumarFalla(db, clave); throw new Falla('Usuario o contraseña incorrectos', 401); }
    await limpiarFallas(db, clave);
    return { token: await crearSesion(db, u.id), usuario: publico(u) };
  },

  async yo({ yo }) { if (!yo) throw new Falla('Tenés que ingresar de nuevo', 401); const { token, ...u } = yo; return { usuario: u }; },
  async salir({ db, yo }) { if (yo) await db.prepare('DELETE FROM sesiones WHERE token=?').bind(yo.token).run(); return { ok: true }; },

  /* ----- cuentas (solo administrador) ----- */
  async usuarios({ db, yo }) {
    exigir(yo, 'admin');
    const r = await db.prepare('SELECT id,nombre,usuario,rol FROM usuarios ORDER BY (rol IS NOT NULL), nombre').all();
    return { usuarios: r.results };
  },
  async usuario_rol({ db, yo, d }) {
    exigir(yo, 'admin');
    const rol = d.rol || null;
    if (rol && !['profe', 'director'].includes(rol)) throw new Falla('Rol inválido');
    await db.prepare('UPDATE usuarios SET rol=? WHERE id=?').bind(rol, d.id).run();
    return { ok: true };
  },
  async usuario_pass({ db, yo, d }) {
    exigir(yo, 'admin');
    if (String(d.pass || '').length < 4) throw new Falla('Contraseña muy corta');
    const sal = hex(crypto.getRandomValues(new Uint8Array(16)));
    await db.batch([
      db.prepare('UPDATE usuarios SET pass=?, sal=? WHERE id=?').bind(await derivar(d.pass, sal), sal, d.id),
      db.prepare('DELETE FROM sesiones WHERE usuario_id=?').bind(d.id),
    ]);
    return { ok: true };
  },
  async usuario_borrar({ db, yo, d }) {
    exigir(yo, 'admin');
    await db.batch([
      db.prepare('DELETE FROM usuarios WHERE id=?').bind(d.id),
      db.prepare('DELETE FROM sesiones WHERE usuario_id=?').bind(d.id),
    ]);
    return { ok: true };
  },

  /* ----- alumnos totales ----- */
  async alumnos({ db, yo }) {
    exigir(yo);
    const r = await db.prepare('SELECT id,apellido,nombre,curso FROM alumnos WHERE activo=1 ORDER BY curso, apellido, nombre').all();
    return { alumnos: r.results };
  },
  async alumnos_agregar({ db, yo, d }) {
    exigir(yo);
    const lista = (Array.isArray(d.alumnos) ? d.alumnos : []).slice(0, 500)
      .map(a => ({ apellido: cap(a.apellido), nombre: cap(a.nombre), curso: curso(a.curso) }))
      .filter(a => (a.apellido || a.nombre) && a.curso);
    const existentes = (await db.prepare('SELECT apellido,nombre,curso FROM alumnos WHERE activo=1').all()).results;
    const ya = new Set(existentes.map(a => `${a.apellido}|${a.nombre}|${a.curso}`.toLowerCase()));
    const nuevos = [];
    for (const a of lista) { const k = `${a.apellido}|${a.nombre}|${a.curso}`.toLowerCase(); if (!ya.has(k)) { ya.add(k); nuevos.push(a); } }
    if (nuevos.length) await db.batch(nuevos.map(a => db.prepare('INSERT INTO alumnos (id,apellido,nombre,curso,activo,creado) VALUES (?,?,?,?,1,?)').bind(id(), a.apellido, a.nombre, a.curso, ahora())));
    return { agregados: nuevos.length, repetidos: lista.length - nuevos.length };
  },
  async alumno_editar({ db, yo, d }) {
    exigir(yo);
    const a = { apellido: cap(d.apellido), nombre: cap(d.nombre), curso: curso(d.curso) };
    if (!(a.apellido || a.nombre) || !a.curso) throw new Falla('Faltan datos del alumno');
    await db.prepare('UPDATE alumnos SET apellido=?, nombre=?, curso=? WHERE id=?').bind(a.apellido, a.nombre, a.curso, d.id).run();
    return { ok: true };
  },
  async alumnos_sacar({ db, yo, d }) {
    exigir(yo);
    const ids = (Array.isArray(d.ids) ? d.ids : []).filter(x => typeof x === 'string').slice(0, 500);
    if (!ids.length) throw new Falla('No hay alumnos para sacar');
    // Se marcan como inactivos: dejan de aparecer pero su historial se conserva
    await db.batch(ids.map(x => db.prepare('UPDATE alumnos SET activo=0 WHERE id=?').bind(x)));
    return { sacados: ids.length };
  },

  /* ----- alumnos asistentes ----- */
  async asistencias({ db, yo, d }) {
    exigir(yo);
    const w = [], b = [];
    if (d.fecha) { if (!FECHA.test(d.fecha)) throw new Falla('Fecha inválida'); w.push('s.fecha=?'); b.push(d.fecha); }
    if (d.curso) { w.push('s.curso=?'); b.push(curso(d.curso)); }
    if (d.alumnoId) { w.push('s.alumno_id=?'); b.push(d.alumnoId); }
    if (d.desde) { w.push('s.fecha>=?'); b.push(d.desde); }
    if (d.hasta) { w.push('s.fecha<=?'); b.push(d.hasta); }
    if (yo.rol === 'profe' && !(d.fecha && d.curso)) throw new Falla('No tenés permiso para esto', 403);
    if (!w.length) throw new Falla('Indicá una fecha o un rango');
    const r = await db.prepare(`SELECT s.fecha, s.alumno_id AS alumnoId, s.curso, s.estado, s.hora, a.apellido, a.nombre
      FROM asistencias s LEFT JOIN alumnos a ON a.id=s.alumno_id WHERE ${w.join(' AND ')} ORDER BY s.fecha DESC, s.curso, a.apellido LIMIT 20000`).bind(...b).all();
    return { asistencias: r.results };
  },
  async asistencia_guardar({ db, yo, d }) {
    exigir(yo);
    if (!FECHA.test(d.fecha || '')) throw new Falla('Fecha inválida');
    const c = curso(d.curso), marcas = d.marcas || {};
    const als = (await db.prepare('SELECT id FROM alumnos WHERE activo=1 AND curso=?').bind(c).all()).results;
    if (!als.length) throw new Falla('Ese curso no tiene alumnos');
    const ts = ahora();
    await db.batch(als.map(a => {
      const m = marcas[a.id] || {};
      const estado = ['P', 'T', 'A'].includes(m.estado) ? m.estado : 'P';
      const hora = estado === 'T' && HORA.test(m.hora || '') ? m.hora : null;
      return db.prepare(`INSERT INTO asistencias (id,fecha,alumno_id,curso,estado,hora,usuario_id,ts) VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(fecha,alumno_id) DO UPDATE SET estado=excluded.estado, hora=excluded.hora, curso=excluded.curso, usuario_id=excluded.usuario_id, ts=excluded.ts`)
        .bind(id(), d.fecha, a.id, c, estado, hora, yo.id, ts);
    }));
    return { guardados: als.length };
  },
  async resumen({ db, yo }) {
    exigir(yo, 'director', 'admin');
    const r = await db.prepare(`SELECT a.id, a.apellido, a.nombre, a.curso, SUM(s.estado='A') AS A, SUM(s.estado='T') AS T
      FROM asistencias s JOIN alumnos a ON a.id=s.alumno_id AND a.activo=1 GROUP BY a.id HAVING A>0 OR T>0 ORDER BY A DESC, T DESC LIMIT 15`).all();
    return { ranking: r.results };
  },

  /* ----- IA (la clave nunca sale del servidor) ----- */
  async ia({ env, yo, d }) {
    exigir(yo);
    if (!env.ANTHROPIC_API_KEY) throw new Falla('Falta configurar la clave de IA en el servidor (ANTHROPIC_API_KEY)', 500);
    const prompt = String(d.prompt || '').slice(0, 30000);
    if (!prompt) throw new Falla('Falta el pedido');
    const content = [];
    if (d.image) {
      if (d.image.length > 7_000_000) throw new Falla('La foto es muy grande');
      content.push({ type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: d.image } });
    }
    content.push({ type: 'text', text: prompt });
    const r = await fetch(env.IA_URL || 'https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: env.IA_MODELO || 'claude-sonnet-5-5', max_tokens: 8000, temperature: 0, messages: [{ role: 'user', content }] }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Falla('La IA respondió con error: ' + (j.error?.message || r.status), 502);
    return { text: (j.content || []).map(b => b.text || '').join('') };
  },
};

export async function manejarApi(request, env, accion) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  try {
    const db = env.DB;
    if (!db) throw new Falla('El servidor no tiene conectada la base de datos (binding D1 "DB").', 500);
    if (!tablasListas) { await db.batch(ESQUEMA.map(s => db.prepare(s))); tablasListas = true; }
    const fn = acciones[accion];
    if (!fn) throw new Falla('Acción desconocida', 404);
    if (request.method !== 'POST' && accion !== 'salud') throw new Falla('Método no permitido', 405);
    const d = request.method === 'POST' ? await request.json().catch(() => ({})) : {};
    const yo = await quienSoy(db, env, request);
    return json(await fn({ db, env, d, yo }));
  } catch (e) {
    return json({ error: e.message || 'Error del servidor' }, e.s || 500);
  }
}
