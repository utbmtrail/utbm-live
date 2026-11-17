// Relais sécurisé entre l'application UTBM Live et Supabase.
//  - Les clés Supabase ne quittent jamais le serveur (variables d'environnement Vercel).
//  - Lecture publique (classement), mise en cache par le CDN de Vercel.
//  - Écriture protégée par PIN :
//      * ajout d'un scan        -> PIN opérateur (Raspberry) ou PIN administrateur
//      * tout le reste          -> PIN administrateur
//  - Liste blanche de tables, validation des scans, limitation des essais de PIN.
//
// Variables d'environnement (Vercel -> Settings -> Environment Variables) :
//   SUPABASE_URL           https://xxxx.supabase.co
//   SUPABASE_SECRET_KEY    clé secrète Supabase (jamais dans le navigateur)
//   OPERATOR_PIN           PIN des Raspberry (6 caractères ou plus)
//   ADMIN_PIN              PIN de l'administrateur (différent du précédent)
const crypto = require('crypto');

const TABLES = new Set(['scans', 'participants', 'config', 'wristbands']);
const TTL = { scans: 10, config: 10, participants: 30, wristbands: 30 }; // secondes de cache CDN
const CHECKPOINT_RE = /^[A-Z0-9_]{1,20}$/;
const MAX_BODY = 300 * 1024;
const fails = new Map(); // ip -> [timestamps] (par instance, en complément du WAF Vercel)

const eq = (a, b) => {
  const A = Buffer.from(String(a || '')), B = Buffer.from(String(b || ''));
  return B.length > 0 && A.length === B.length && crypto.timingSafeEqual(A, B);
};
const sleep = ms => new Promise(r => setTimeout(r, ms));

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'content-type,prefer,x-operator-pin,x-admin-pin');
  res.setHeader('Access-Control-Expose-Headers', 'content-range');
  res.setHeader('Access-Control-Max-Age', '86400');
}
function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

function validScan(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const keys = Object.keys(o);
  if (keys.some(k => !['badge_id', 'checkpoint', 'timestamp', 'source'].includes(k))) return false;
  if (typeof o.badge_id !== 'string' || !o.badge_id || o.badge_id.length > 64) return false;
  if (typeof o.checkpoint !== 'string' || !CHECKPOINT_RE.test(o.checkpoint)) return false;
  if (typeof o.timestamp !== 'string' || isNaN(Date.parse(o.timestamp))) return false;
  if (o.source != null && o.source !== 'organisation') return false;
  return true;
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }

  const { SUPABASE_URL, SUPABASE_SECRET_KEY, OPERATOR_PIN, ADMIN_PIN } = process.env;
  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) return send(res, 500, { error: 'Serveur non configuré' });

  const url = new URL(req.url, 'http://relay');
  const m = url.pathname.match(/\/rest\/v1\/([a-z_]+)$/);
  const table = url.searchParams.get('__t') || (m && m[1]);
  url.searchParams.delete('__t');
  if (!table || !TABLES.has(table)) return send(res, 404, { error: 'Table inconnue' });
  if (!['GET', 'POST', 'DELETE'].includes(req.method)) return send(res, 405, { error: 'Méthode refusée' });

  const headers = { apikey: SUPABASE_SECRET_KEY, Authorization: 'Bearer ' + SUPABASE_SECRET_KEY };
  let body;

  if (req.method !== 'GET') {
    // ── Authentification ──
    const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'x';
    const now = Date.now();
    const recent = (fails.get(ip) || []).filter(t => now - t < 60000);
    if (recent.length >= 8) return send(res, 429, { error: 'Trop d\'essais, patientez une minute' });

    const adminPin = ADMIN_PIN || OPERATOR_PIN;
    const op = req.headers['x-operator-pin'], ad = req.headers['x-admin-pin'];
    const isAdmin = eq(ad, adminPin) || eq(op, adminPin);
    const isOperator = isAdmin || eq(op, OPERATOR_PIN) || eq(ad, OPERATOR_PIN);
    const needAdmin = !(table === 'scans' && req.method === 'POST');
    if (needAdmin ? !isAdmin : !isOperator) {
      recent.push(now); fails.set(ip, recent);
      await sleep(500);
      return send(res, 401, { error: 'PIN incorrect', need: needAdmin ? 'admin' : 'operator' });
    }

    // ── Contrôle du contenu ──
    if (req.method === 'DELETE') {
      if (![...url.searchParams.keys()].length) return send(res, 400, { error: 'Filtre obligatoire' });
    } else {
      body = typeof req.body === 'string' ? JSON.parse(req.body || 'null') : req.body;
      const txt = JSON.stringify(body || null);
      if (!body || txt.length > MAX_BODY) return send(res, 400, { error: 'Corps invalide ou trop gros' });
      if (table === 'scans') {
        const list = Array.isArray(body) ? body : [body];
        if (list.length > 500 || !list.every(validScan)) return send(res, 400, { error: 'Scan invalide' });
      }
      headers['Content-Type'] = 'application/json';
    }
    const pref = req.headers.prefer;
    if (pref === 'return=minimal' || pref === 'return=representation') headers.Prefer = pref;
  }

  let up;
  try {
    up = await fetch(SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/' + table + url.search, {
      method: req.method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) { return send(res, 502, { error: 'Base de données injoignable' }); }

  const text = await up.text();
  res.statusCode = up.status;
  res.setHeader('Content-Type', up.headers.get('content-type') || 'application/json');
  const cr = up.headers.get('content-range'); if (cr) res.setHeader('Content-Range', cr);
  if (req.method === 'GET' && up.ok) {
    // La vérification « un seul coureur à la fois » doit voir les scans en direct : pas de cache.
    const live = table === 'scans' && url.search.includes('badge_id=in.');
    res.setHeader('Cache-Control', live ? 'no-store' : 'public, s-maxage=' + TTL[table] + ', stale-while-revalidate=' + TTL[table] * 2);
  } else res.setHeader('Cache-Control', 'no-store');
  res.end(text);
};
