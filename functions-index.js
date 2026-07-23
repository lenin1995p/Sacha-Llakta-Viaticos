/**
 * Sacha Llakta Viáticos — Webhook de pagos de Stripe
 * ------------------------------------------------------
 * Cuando un cliente completa un pago en Stripe, Stripe llama a esta función.
 * La función verifica la firma, identifica la empresa (client_reference_id) y
 * el plan comprado, y actualiza companies/{companyId}.plan en Firestore.
 */

const { onRequest } = require("firebase-functions/v2/https");
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { defineSecret } = require("firebase-functions/params");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");
const Stripe = require("stripe");

admin.initializeApp();

// Secretos (se configuran con: firebase functions:secrets:set NOMBRE)
const STRIPE_SECRET_KEY = defineSecret("STRIPE_SECRET_KEY");
const STRIPE_WEBHOOK_SECRET = defineSecret("STRIPE_WEBHOOK_SECRET");
const RESEND_API_KEY = defineSecret("RESEND_API_KEY");

// Respaldo: monto (en centavos) -> plan, por si el client_reference_id no trae el plan.
function planFromAmount(amount) {
  if (amount === 999) return "basic";       // $9.99
  if (amount === 2499) return "pro";        // $24.99
  if (amount === 5999) return "enterprise"; // $59.99
  return null;
}

const VALID_PLANS = ["basic", "pro", "enterprise"];

exports.stripeWebhook = onRequest(
  { secrets: [STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET], region: "us-central1" },
  async (req, res) => {
    const stripe = new Stripe(STRIPE_SECRET_KEY.value());

    // 1) Verificar que el evento realmente viene de Stripe (firma).
    let event;
    try {
      const sig = req.headers["stripe-signature"];
      event = stripe.webhooks.constructEvent(
        req.rawBody,
        sig,
        STRIPE_WEBHOOK_SECRET.value()
      );
    } catch (err) {
      logger.error("Firma inválida:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      // 2) Pago completado -> activar la empresa.
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const ref = session.client_reference_id || "";
        const parts = ref.split("__");
        const companyId = parts[0] || null;
        let plan = parts[1] || null;

        // Si no vino el plan en la referencia, dedúcelo del monto.
        if (!VALID_PLANS.includes(plan)) {
          const amt = session.amount_subtotal != null
            ? session.amount_subtotal
            : session.amount_total;
          plan = planFromAmount(amt);
        }

        if (!companyId) {
          logger.warn("Sin client_reference_id; se ignora.", session.id);
          return res.status(200).send("Sin referencia de empresa; ignorado.");
        }
        if (!VALID_PLANS.includes(plan)) {
          logger.warn("Plan no reconocido; se ignora.", { ref, amount: session.amount_total });
          return res.status(200).send("Plan no reconocido; ignorado.");
        }

        await admin.firestore().collection("companies").doc(companyId).set(
          {
            plan: plan,
            planStart: admin.firestore.FieldValue.serverTimestamp(),
            paidActive: true,
            stripeCustomerId: session.customer || null,
            stripeSubscriptionId: session.subscription || null,
            lastPaymentAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );

        logger.info(`Empresa ${companyId} activada con plan ${plan}.`);
        return res.status(200).send("ok");
      }

      // 3) Suscripción actualizada (cambio de plan / cancelación programada vía Portal).
      if (event.type === "customer.subscription.updated") {
        const sub = event.data.object;
        const snap = await admin.firestore().collection("companies")
          .where("stripeSubscriptionId", "==", sub.id).limit(1).get();
        if (!snap.empty) {
          const updates = { cancelAtPeriodEnd: !!sub.cancel_at_period_end };
          // Nuevo plan según el precio actual de la suscripción.
          try {
            const amt = sub.items && sub.items.data && sub.items.data[0] && sub.items.data[0].price
              ? sub.items.data[0].price.unit_amount : null;
            const p = planFromAmount(amt);
            if (p) { updates.plan = p; updates.paidActive = true; }
          } catch (e) {}
          if (sub.current_period_end) {
            updates.currentPeriodEnd = admin.firestore.Timestamp.fromMillis(sub.current_period_end * 1000);
          }
          await snap.docs[0].ref.set(updates, { merge: true });
          logger.info(`Empresa ${snap.docs[0].id}: suscripción actualizada -> ${updates.plan || "(sin cambio de plan)"}, cancelAtPeriodEnd=${sub.cancel_at_period_end}.`);
        }
        return res.status(200).send("ok");
      }

      // 4) Suscripción cancelada por completo -> bloquear la empresa.
      if (event.type === "customer.subscription.deleted") {
        const sub = event.data.object;
        const snap = await admin
          .firestore()
          .collection("companies")
          .where("stripeSubscriptionId", "==", sub.id)
          .limit(1)
          .get();
        if (!snap.empty) {
          await snap.docs[0].ref.set(
            { plan: "expired", paidActive: false, cancelAtPeriodEnd: false },
            { merge: true }
          );
          logger.info(`Empresa ${snap.docs[0].id}: suscripción cancelada -> expired.`);
        }
        return res.status(200).send("ok");
      }

      // Otros eventos: los aceptamos para que Stripe no reintente.
      return res.status(200).send("ok");
    } catch (err) {
      logger.error("Error procesando el evento:", err);
      return res.status(500).send("Error interno");
    }
  }
);

/**
 * Genera un enlace al Portal de Cliente de Stripe para el usuario autenticado.
 * El cliente (app) llama con su token de sesión de Firebase; la función deriva
 * la empresa (companies/{uid}), toma su stripeCustomerId y crea la sesión del portal.
 * Así cada usuario solo puede abrir SU propio portal (upgrade/downgrade/cancelar/tarjeta).
 */
exports.createPortalSession = onRequest(
  { secrets: [STRIPE_SECRET_KEY], region: "us-central1" },
  async (req, res) => {
    // CORS (la app vive en otro dominio).
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
    if (req.method === "OPTIONS") { res.status(204).send(""); return; }
    try {
      const authz = req.headers.authorization || "";
      const m = authz.match(/^Bearer (.+)$/);
      if (!m) { res.status(401).json({ error: "No autenticado" }); return; }
      const decoded = await admin.auth().verifyIdToken(m[1]);
      const uid = decoded.uid;
      const snap = await admin.firestore().collection("companies").doc(uid).get();
      if (!snap.exists) { res.status(404).json({ error: "Sin empresa" }); return; }
      const cust = snap.data().stripeCustomerId;
      if (!cust) { res.status(400).json({ error: "Sin suscripción activa" }); return; }
      const stripe = new Stripe(STRIPE_SECRET_KEY.value());
      const session = await stripe.billingPortal.sessions.create({
        customer: cust,
        return_url: "https://viaticos.sachallakta.com/sacha-llakta-supervisor.html",
      });
      res.json({ url: session.url });
    } catch (err) {
      logger.error("createPortalSession error:", err);
      res.status(500).json({ error: err.message });
    }
  }
);

/**
 * ═══════════════════════════════════════════════════════════════════
 * OCR DE RECIBOS (Cloud Vision API) — función insignia
 * ═══════════════════════════════════════════════════════════════════
 * El empleado toma foto del recibo -> la app llama aquí -> Vision lee el
 * texto -> devolvemos monto total, comercio y fecha detectados.
 *
 * Seguridad (los empleados no usan Firebase Auth):
 *  - Se exige companyId + employeeId + code, y se verifica que el código
 *    coincida con el documento del empleado en Firestore.
 *  - Límite de 40 escaneos por empleado por día (protege el crédito).
 *  - Límite de tamaño de imagen (~1.8 MB en base64).
 * La clave nunca sale del servidor: usamos las credenciales por defecto
 * del proyecto (ADC) con un token de acceso — no hay API key expuesta.
 */
const { GoogleAuth } = require("google-auth-library");

const OCR_DAILY_LIMIT = 40;
const OCR_MAX_B64 = 1.8 * 1024 * 1024; // ~1.8 MB de base64

// ── Interpretación del texto del recibo ──────────────────────────────
function parseMoney(str) {
  let s = String(str).replace(/[^\d.,]/g, "");
  if (!s) return null;
  const lastDot = s.lastIndexOf("."), lastCom = s.lastIndexOf(",");
  if (lastDot >= 0 && lastCom >= 0) {
    if (lastDot > lastCom) s = s.replace(/,/g, "");
    else s = s.replace(/\./g, "").replace(",", ".");
  } else if (lastCom >= 0) {
    s = /,\d{2}$/.test(s) ? s.replace(",", ".") : s.replace(/,/g, "");
  }
  const n = parseFloat(s);
  return isNaN(n) ? null : Math.round(n * 100) / 100;
}

// Marcas conocidas -> nombre limpio. Se busca en TODO el texto del recibo,
// porque muchos recibos entierran el nombre real bajo texto de relleno.
const BRANDS = [
  [/mc\s?donald'?s?/i, "McDonald's"], [/\bwal[\s-]?mart\b/i, "Walmart"],
  [/\btarget\b/i, "Target"], [/\bcostco\b/i, "Costco"], [/sam'?s club/i, "Sam's Club"],
  [/\bkroger\b/i, "Kroger"], [/\bdillons\b/i, "Dillons"], [/\baldi\b/i, "Aldi"],
  [/quik\s?trip|\bqt\s?#/i, "QuikTrip"], [/casey'?s/i, "Casey's"], [/kwik\s?shop/i, "Kwik Shop"],
  [/love'?s\s+(travel|country)/i, "Love's"], [/\bpilot\s+(travel|flying)/i, "Pilot"],
  [/flying\s+j/i, "Flying J"], [/\bshell\b/i, "Shell"], [/\bexxon/i, "Exxon"],
  [/\bchevron\b/i, "Chevron"], [/phillips\s*66/i, "Phillips 66"], [/\bconoco\b/i, "Conoco"],
  [/\bsinclair\b/i, "Sinclair"], [/\bvalero\b/i, "Valero"], [/circle\s?k/i, "Circle K"],
  [/murphy\s?(usa|express)/i, "Murphy USA"], [/\bsubway\b/i, "Subway"],
  [/burger\s?king/i, "Burger King"], [/wendy'?s/i, "Wendy's"], [/taco\s?bell/i, "Taco Bell"],
  [/\bkfc\b|kentucky fried/i, "KFC"], [/popeyes/i, "Popeyes"], [/chick[\s-]?fil[\s-]?a/i, "Chick-fil-A"],
  [/chipotle/i, "Chipotle"], [/panda\s?express/i, "Panda Express"], [/\bsonic\b/i, "Sonic"],
  [/braum'?s/i, "Braum's"], [/applebee'?s/i, "Applebee's"], [/chili'?s/i, "Chili's"],
  [/\bihop\b/i, "IHOP"], [/denny'?s/i, "Denny's"], [/cracker\s?barrel/i, "Cracker Barrel"],
  [/olive\s?garden/i, "Olive Garden"], [/buffalo\s?wild\s?wings/i, "Buffalo Wild Wings"],
  [/pizza\s?hut/i, "Pizza Hut"], [/domino'?s/i, "Domino's"], [/papa\s?john'?s/i, "Papa John's"],
  [/starbucks/i, "Starbucks"], [/dunkin/i, "Dunkin'"], [/jimmy\s?john'?s/i, "Jimmy John's"],
  [/\bhardee'?s/i, "Hardee's"], [/\barby'?s/i, "Arby's"], [/whataburger/i, "Whataburger"],
  [/freddy'?s/i, "Freddy's"], [/spangles/i, "Spangles"],
  [/home\s?depot/i, "Home Depot"], [/lowe'?s/i, "Lowe's"], [/harbor\s?freight/i, "Harbor Freight"],
  [/menards/i, "Menards"], [/ace\s?hardware/i, "Ace Hardware"], [/tractor\s?supply/i, "Tractor Supply"],
  [/o'?reilly/i, "O'Reilly"], [/autozone/i, "AutoZone"], [/\bnapa\b/i, "NAPA"],
  [/grainger/i, "Grainger"], [/fastenal/i, "Fastenal"], [/northern\s?tool/i, "Northern Tool"],
  [/hampton\s?inn/i, "Hampton Inn"], [/holiday\s?inn/i, "Holiday Inn"], [/best\s?western/i, "Best Western"],
  [/la\s?quinta/i, "La Quinta"], [/comfort\s?(inn|suites)/i, "Comfort Inn"], [/days\s?inn/i, "Days Inn"],
  [/super\s?8/i, "Super 8"], [/motel\s?6/i, "Motel 6"], [/marriott/i, "Marriott"],
  [/hilton/i, "Hilton"], [/fairfield\s?inn/i, "Fairfield Inn"], [/\bwyndham\b/i, "Wyndham"],
  [/\buber\b/i, "Uber"], [/\blyft\b/i, "Lyft"], [/\bhertz\b/i, "Hertz"],
  [/enterprise\s?rent/i, "Enterprise Rent-A-Car"], [/\bavis\b/i, "Avis"],
  [/walgreens/i, "Walgreens"], [/\bcvs\b/i, "CVS"], [/dollar\s?general/i, "Dollar General"],
  [/dollar\s?tree/i, "Dollar Tree"], [/family\s?dollar/i, "Family Dollar"],
];

// Líneas de relleno que NO son el nombre del comercio.
const BOILER = /(locally owned|operated by|we welcome|comments|feedback|survey|thank\s?you|valued customer|welcome to|customer copy|merchant copy|come see us|sign up|rewards|points|visit us|follow us|store\s*#|reg\s*#|cashier|server\s*:|order\s*#|locator|receipt|invoice|factura|www\.|http|@|tel\s*[#:.]|phone|^\s*\d[\d\s.,#*\/-]*$)/i;

function extractReceiptData(fullText) {
  const lines = fullText.split("\n").map(l => l.trim()).filter(Boolean);
  const moneyRe = /\$?\s*(\d{1,3}(?:[.,]\d{3})*[.,]\d{2})(?!\d)/g;

  const totalKey = /(total\s*a\s*pagar|grand\s*total|amount\s*due|balance\s*due|total\s*due|importe\s*total|eat[\s-]?in\s*total|\btotal\b|monto\s*total)/i;
  const antiKey = /(sub\s*-?\s*total|subtotal|total\s*items|total\s*savings|total\s*discount|total\s*tax|total\s*qty|total\s*art)/i;

  // Todos los montos con su línea, y cuántas veces aparece cada valor.
  const all = [], freq = {};
  lines.forEach((line, i) => {
    let m; moneyRe.lastIndex = 0;
    while ((m = moneyRe.exec(line)) !== null) {
      const v = parseMoney(m[1]);
      if (v !== null && v > 0 && v < 100000) { all.push({ v, i }); freq[v] = (freq[v] || 0) + 1; }
    }
  });

  let amount = null;

  // 1) Etiqueta de total con número en la misma línea (recibos alineados).
  const sameLine = [];
  lines.forEach((line, i) => {
    if (!totalKey.test(line) || antiKey.test(line)) return;
    let m; moneyRe.lastIndex = 0;
    while ((m = moneyRe.exec(line)) !== null) {
      const v = parseMoney(m[1]);
      if (v !== null && v > 0 && v < 100000) sameLine.push(v);
    }
  });
  if (sameLine.length) amount = Math.max(...sameLine);

  // 2) Sin número en la línea: el valor que MÁS SE REPITE suele ser el total
  //    (aparece en Total, Pago, Tarjeta, Monto de transacción...).
  if (amount === null && all.length) {
    const maxFreq = Math.max(...Object.values(freq));
    if (maxFreq >= 2) {
      const repeated = Object.keys(freq).filter(k => freq[k] === maxFreq).map(Number);
      amount = Math.max(...repeated);
    } else {
      amount = Math.max(...all.map(x => x.v));
    }
  }

  // Fecha
  let date = null;
  const dateRe = /\b(\d{1,2}[\/\-.]\d{1,2}[\/\-.](?:\d{4}|\d{2}))\b|\b((?:ene|feb|mar|abr|may|jun|jul|ago|sep|oct|nov|dic|jan|apr|aug|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b/i;
  const dm = fullText.match(dateRe);
  if (dm) date = (dm[1] || dm[2] || "").trim();

  // Comercio: 1) marca conocida en todo el texto  2) heurística sin relleno
  let merchant = null;
  for (const [re, name] of BRANDS) { if (re.test(fullText)) { merchant = name; break; } }
  if (!merchant) {
    for (const line of lines.slice(0, 12)) {
      const letters = (line.match(/[A-Za-zÁÉÍÓÚÑáéíóúñ]/g) || []).length;
      if (letters < 3) continue;
      if (BOILER.test(line)) continue;
      if (/^\d/.test(line) && letters < 6) continue;
      merchant = line.replace(/\s{2,}/g, " ").slice(0, 48);
      break;
    }
  }
  return { amount, date, merchant };
}

exports.ocrReceipt = onRequest(
  { region: "us-central1", memory: "512MiB", timeoutSeconds: 60 },
  async (req, res) => {
    // CORS (la app vive en viaticos.sachallakta.com)
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") { res.status(204).send(""); return; }
    if (req.method !== "POST") { res.status(405).json({ error: "Método no permitido" }); return; }

    try {
      const { companyId, employeeId, code, image, supervisor, idToken } = req.body || {};
      if (!companyId || !image) {
        res.status(400).json({ error: "Faltan datos" }); return;
      }

      // Aceptar dataURL o base64 crudo
      const b64 = String(image).replace(/^data:image\/\w+;base64,/, "");
      if (b64.length > OCR_MAX_B64) {
        res.status(413).json({ error: "Imagen demasiado grande" }); return;
      }

      // ── AUTORIZACIÓN ──
      // Camino A: supervisor autenticado con Firebase (token de sesión).
      // Camino B: empleado, verificado por código + límite diario.
      let empRef = null, empSnap = null;
      if (supervisor) {
        if (!idToken) { res.status(401).json({ error: "No autenticado" }); return; }
        let decoded;
        try { decoded = await admin.auth().verifyIdToken(idToken); }
        catch (e) { res.status(401).json({ error: "Token inválido" }); return; }
        // El supervisor debe pertenecer a esta empresa (dueño o supervisor vinculado).
        const uid = decoded.uid;
        const compSnap = await admin.firestore().collection("companies").doc(companyId).get();
        const isOwner = compSnap.exists && uid === companyId;
        let isLinked = false;
        if (!isOwner) {
          const linkSnap = await admin.firestore()
            .collection("companies").doc(companyId)
            .collection("supervisors").doc(uid).get();
          isLinked = linkSnap.exists;
        }
        if (!isOwner && !isLinked) { res.status(403).json({ error: "No autorizado" }); return; }
        // (Los supervisores no tienen límite diario; su volumen es bajo y controlado.)
      } else {
        if (!employeeId || !code) { res.status(400).json({ error: "Faltan datos" }); return; }
        // 1) Verificar que el empleado existe y el código coincide.
        empRef = admin.firestore()
          .collection("companies").doc(companyId)
          .collection("employees").doc(employeeId);
        empSnap = await empRef.get();
        if (!empSnap.exists || empSnap.data().code !== code) {
          res.status(403).json({ error: "No autorizado" }); return;
        }
        // 2) Límite diario por empleado (protege el crédito de Vision).
        const today = new Date().toISOString().slice(0, 10);
        const ocr = empSnap.data().ocrUsage || {};
        const used = (ocr.d === today) ? (ocr.n || 0) : 0;
        if (used >= OCR_DAILY_LIMIT) {
          res.status(429).json({ error: "Límite diario de escaneos alcanzado" }); return;
        }
        empRef.set({ ocrUsage: { d: today, n: used + 1 } }, { merge: true }).catch(() => {});
      }

      // 3) Llamar a Cloud Vision con las credenciales del proyecto (sin API key).
      const auth = new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
      const client = await auth.getClient();
      const tokenResp = await client.getAccessToken();
      const accessToken = tokenResp && (tokenResp.token || tokenResp);

      const visionResp = await fetch("https://vision.googleapis.com/v1/images:annotate", {
        method: "POST",
        headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          requests: [{
            image: { content: b64 },
            features: [{ type: "DOCUMENT_TEXT_DETECTION" }],
            imageContext: { languageHints: ["es", "en"] },
          }],
        }),
      });
      const data = await visionResp.json();
      if (!visionResp.ok) {
        logger.error("Vision API error:", JSON.stringify(data).slice(0, 500));
        res.status(502).json({ error: "Error del servicio de OCR" }); return;
      }

      const r0 = (data.responses && data.responses[0]) || {};
      if (r0.error) {
        logger.error("Vision response error:", r0.error.message);
        res.status(502).json({ error: "No se pudo procesar la imagen" }); return;
      }
      const fullText = (r0.fullTextAnnotation && r0.fullTextAnnotation.text) || "";
      if (!fullText.trim()) {
        res.json({ ok: true, found: false }); return;
      }

      const parsed = extractReceiptData(fullText);
      logger.info(`OCR ${companyId}/${employeeId || "(supervisor)"}: monto=${parsed.amount} comercio="${parsed.merchant}"`);
      res.json({ ok: true, found: true, ...parsed });
    } catch (err) {
      logger.error("ocrReceipt error:", err);
      res.status(500).json({ error: "Error interno" });
    }
  }
);

/**
 * ═══════════════════════════════════════════════════════════════════
 * CORREO DE BIENVENIDA (Resend)
 * ═══════════════════════════════════════════════════════════════════
 * Se dispara solo cuando se crea companies/{companyId} en Firestore.
 * Al ser un trigger de servidor, es confiable aunque el usuario cierre
 * la pestaña justo después de registrarse.
 */
const FROM_EMAIL = "Sacha Llakta Viáticos <viaticos@mail.sachallakta.com>";
const APP_SUP_URL = "https://viaticos.sachallakta.com/sacha-llakta-supervisor.html";

function esc(s){
  return String(s==null?"":s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;");
}

// Envía un correo vía la API REST de Resend (sin SDK, para no agregar dependencias).
async function sendEmail({ to, subject, html, replyTo }) {
  const body = {
    from: FROM_EMAIL,
    to: Array.isArray(to) ? to : [to],
    subject,
    html,
  };
  if (replyTo) body.reply_to = replyTo;
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY.value()}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(`Resend ${resp.status}: ${JSON.stringify(data).slice(0, 300)}`);
  }
  return data;
}

function welcomeHtml({ company, name, code }) {
  const codeBlock = code
    ? `<p style="margin:0 0 8px;color:#94a3b8;font-size:13px;letter-spacing:.5px">CÓDIGO DE TU EMPRESA</p>
       <div style="font-family:ui-monospace,Menlo,monospace;font-size:22px;font-weight:700;color:#e3a94a;background:#0f1629;border:1px solid #1f2d45;border-radius:10px;padding:14px 18px;text-align:center;letter-spacing:2px">${esc(code)}</div>
       <p style="margin:12px 0 0;color:#94a3b8;font-size:13px;line-height:1.6">Comparte este código con tus supervisores para que se unan a la empresa. Guárdalo en un lugar seguro.</p>`
    : "";
  return `<!doctype html><html><body style="margin:0;background:#0a0f1e;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
    <div style="max-width:560px;margin:0 auto;padding:32px 20px">
      <div style="text-align:center;margin-bottom:28px">
        <div style="font-size:13px;letter-spacing:3px;color:#e3a94a;font-weight:700">SACHA LLAKTA</div>
        <div style="font-size:12px;letter-spacing:2px;color:#64748b">VIÁTICOS</div>
      </div>
      <div style="background:#111827;border:1px solid #1f2d45;border-radius:16px;padding:28px 24px">
        <h1 style="margin:0 0 12px;color:#f1f5f9;font-size:22px">¡Bienvenido, ${esc(name || "")}! 👋</h1>
        <p style="margin:0 0 20px;color:#cbd5e1;font-size:15px;line-height:1.65">
          Tu empresa <b style="color:#f1f5f9">${esc(company || "")}</b> ya está registrada en Sacha Llakta Viáticos.
          Desde tu panel puedes agregar empleados, asignar viáticos y llevar el control de cada viaje.
        </p>
        ${codeBlock}
        <div style="text-align:center;margin:26px 0 8px">
          <a href="${APP_SUP_URL}" style="display:inline-block;background:#e3a94a;color:#0a0f1e;font-weight:700;font-size:15px;text-decoration:none;padding:13px 28px;border-radius:10px">Abrir mi panel</a>
        </div>
      </div>
      <p style="text-align:center;color:#475569;font-size:12px;line-height:1.6;margin-top:22px">
        Recibiste este correo porque creaste una cuenta en Sacha Llakta Viáticos.<br>
        ¿Preguntas? Responde a este correo.
      </p>
    </div>
  </body></html>`;
}

exports.sendWelcomeEmail = onDocumentCreated(
  { document: "companies/{companyId}", secrets: [RESEND_API_KEY], region: "us-central1" },
  async (event) => {
    const snap = event.data;
    if (!snap) return;
    const d = snap.data() || {};
    const to = d.supervisorEmail;
    if (!to) { logger.warn("Empresa sin supervisorEmail; no se envía bienvenida."); return; }

    // El código puede reservarse un instante después de crear el doc; damos margen.
    let code = d.companyCode || null;
    if (!code) {
      await new Promise(r => setTimeout(r, 4000));
      try {
        const fresh = await admin.firestore().collection("companies").doc(event.params.companyId).get();
        code = (fresh.data() || {}).companyCode || null;
      } catch (e) {}
    }

    try {
      await sendEmail({
        to,
        replyTo: "leninp@sachallakta.com",
        subject: `Bienvenido a Sacha Llakta Viáticos — ${d.company || ""}`.trim(),
        html: welcomeHtml({ company: d.company, name: d.supervisorName, code }),
      });
      logger.info(`Bienvenida enviada a ${to} (${d.company || "?"}).`);
    } catch (err) {
      logger.error("Error enviando bienvenida:", err.message);
    }
  }
);

/**
 * ═══════════════════════════════════════════════════════════════════
 * ELIMINAR EMPRESA POR COMPLETO (solo superadmin)
 * ═══════════════════════════════════════════════════════════════════
 * El panel de superadmin no puede borrar cuentas de Firebase Auth desde el
 * navegador (solo el Admin SDK puede). Por eso, al borrar una empresa desde
 * la app quedaba viva la cuenta del supervisor y su correo seguía "en uso".
 * Esta función hace la limpieza completa:
 *   · subcolecciones: employees, expenses, trips, supervisors
 *   · codes/{código} de cada empleado
 *   · companyCodes/{código de empresa}
 *   · supervisorLinks de los supervisores invitados + sus cuentas Auth
 *   · la cuenta Auth del supervisor dueño  ← lo que libera el correo
 *   · el documento companies/{companyId}
 */
const ADMIN_EMAILS = [
  "lenin1995p@icloud.com",
  "leninp@sachallakta.com",
  "lenin1995p@gmail.com",
];

// Borra todos los documentos de una colección en lotes (evita timeouts).
async function deleteCollection(ref, batchSize = 300) {
  let deleted = 0;
  while (true) {
    const snap = await ref.limit(batchSize).get();
    if (snap.empty) break;
    const batch = admin.firestore().batch();
    snap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();
    deleted += snap.size;
    if (snap.size < batchSize) break;
  }
  return deleted;
}

exports.adminDeleteCompany = onRequest(
  { region: "us-central1", timeoutSeconds: 300, memory: "512MiB" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
    if (req.method === "OPTIONS") { res.status(204).send(""); return; }
    if (req.method !== "POST") { res.status(405).json({ error: "Método no permitido" }); return; }

    try {
      // 1) Solo un superadmin autenticado puede llamar aquí.
      const authz = req.headers.authorization || "";
      const m = authz.match(/^Bearer (.+)$/);
      if (!m) { res.status(401).json({ error: "No autenticado" }); return; }
      let decoded;
      try { decoded = await admin.auth().verifyIdToken(m[1]); }
      catch (e) { res.status(401).json({ error: "Token inválido" }); return; }
      const callerEmail = (decoded.email || "").toLowerCase();
      if (!ADMIN_EMAILS.map((e) => e.toLowerCase()).includes(callerEmail)) {
        res.status(403).json({ error: "No autorizado" }); return;
      }

      const companyId = (req.body && req.body.companyId) || null;
      if (!companyId) { res.status(400).json({ error: "Falta companyId" }); return; }

      // Protección: nunca borrar la cuenta con la que estás administrando ahora
      // mismo (te dejaría fuera del panel de superadmin).
      if (companyId === decoded.uid) {
        res.status(400).json({
          error: "No puedes eliminar la empresa de la cuenta con la que estás conectado. Entra con otra cuenta de administrador.",
        });
        return;
      }

      const db = admin.firestore();
      const companyRef = db.collection("companies").doc(companyId);
      const companySnap = await companyRef.get();
      if (!companySnap.exists) { res.status(404).json({ error: "Empresa no encontrada" }); return; }
      const company = companySnap.data() || {};
      const report = { employees: 0, expenses: 0, trips: 0, codes: 0, supervisors: 0, authDeleted: [] };

      // 2) Códigos de acceso de los empleados (colección raíz 'codes').
      const empsSnap = await companyRef.collection("employees").get();
      for (const d of empsSnap.docs) {
        const code = (d.data() || {}).code;
        if (code) {
          try { await db.collection("codes").doc(code).delete(); report.codes++; } catch (e) {}
        }
      }

      // 3) Subcolecciones de la empresa.
      report.employees = await deleteCollection(companyRef.collection("employees"));
      report.expenses  = await deleteCollection(companyRef.collection("expenses"));
      report.trips     = await deleteCollection(companyRef.collection("trips"));
      try { await deleteCollection(companyRef.collection("supervisors")); } catch (e) {}

      // 4) Código de empresa (para unirse).
      if (company.companyCode) {
        try { await db.collection("companyCodes").doc(company.companyCode).delete(); } catch (e) {}
      }

      // 5) Supervisores invitados: su vínculo y su cuenta Auth.
      try {
        const links = await db.collection("supervisorLinks").where("companyId", "==", companyId).get();
        for (const l of links.docs) {
          const supUid = l.id;
          try { await l.ref.delete(); report.supervisors++; } catch (e) {}
          if (supUid !== companyId) {
            try {
              const u = await admin.auth().getUser(supUid);
              await admin.auth().deleteUser(supUid);
              report.authDeleted.push(u.email || supUid);
            } catch (e) { /* la cuenta ya no existe */ }
          }
        }
      } catch (e) { logger.warn("supervisorLinks:", e.message); }

      // 6) La cuenta del supervisor dueño. El id del documento de empresa ES su uid,
      //    así que borrarla libera el correo para poder registrarse de nuevo.
      try {
        const owner = await admin.auth().getUser(companyId);
        await admin.auth().deleteUser(companyId);
        report.authDeleted.push(owner.email || companyId);
      } catch (e) {
        logger.warn("No se pudo borrar la cuenta del dueño:", e.message);
      }

      // 7) Finalmente, el documento de la empresa.
      await companyRef.delete();

      logger.info(`Empresa ${companyId} (${company.company || "?"}) eliminada por ${callerEmail}.`, report);
      res.json({ ok: true, ...report });
    } catch (err) {
      logger.error("adminDeleteCompany error:", err);
      res.status(500).json({ error: err.message });
    }
  }
);
