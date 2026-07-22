/**
 * Sacha Llakta Viáticos — Webhook de pagos de Stripe
 * ------------------------------------------------------
 * Cuando un cliente completa un pago en Stripe, Stripe llama a esta función.
 * La función verifica la firma, identifica la empresa (client_reference_id) y
 * el plan comprado, y actualiza companies/{companyId}.plan en Firestore.
 */

const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");
const Stripe = require("stripe");

admin.initializeApp();

// Secretos (se configuran con: firebase functions:secrets:set NOMBRE)
const STRIPE_SECRET_KEY = defineSecret("STRIPE_SECRET_KEY");
const STRIPE_WEBHOOK_SECRET = defineSecret("STRIPE_WEBHOOK_SECRET");

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
  // Acepta 1,234.56 / 1.234,56 / 45.67 / 45,67 -> número JS
  let s = String(str).replace(/[^\d.,]/g, "");
  if (!s) return null;
  const lastDot = s.lastIndexOf("."), lastCom = s.lastIndexOf(",");
  if (lastDot >= 0 && lastCom >= 0) {
    // El separador decimal es el que aparece más a la derecha
    if (lastDot > lastCom) s = s.replace(/,/g, "");
    else s = s.replace(/\./g, "").replace(",", ".");
  } else if (lastCom >= 0) {
    // Solo comas: si hay 2 decimales al final es decimal, si no, miles
    s = /,\d{2}$/.test(s) ? s.replace(",", ".") : s.replace(/,/g, "");
  }
  const n = parseFloat(s);
  return isNaN(n) ? null : Math.round(n * 100) / 100;
}

function extractReceiptData(fullText) {
  const lines = fullText.split("\n").map(l => l.trim()).filter(Boolean);
  const moneyRe = /\$?\s*(\d{1,3}(?:[.,]\d{3})*[.,]\d{2})(?!\d)/g;

  // ── Monto total ──
  // 1) Buscar líneas con palabras clave de total (excluyendo subtotal).
  const totalKey = /(total\s*a\s*pagar|grand\s*total|amount\s*due|balance\s*due|total\s*due|importe\s*total|\btotal\b|monto\s*total)/i;
  const antiKey = /(sub\s*-?\s*total|subtotal|total\s*items|total\s*savings|total\s*discount|total\s*tax|total\s*qty|total\s*art)/i;
  let candidates = [];
  lines.forEach((line, i) => {
    if (!totalKey.test(line) || antiKey.test(line)) return;
    // El número puede estar en la misma línea o en la siguiente (formato de columnas)
    const searchIn = [line, lines[i + 1] || ""];
    for (const src of searchIn) {
      let m; moneyRe.lastIndex = 0;
      while ((m = moneyRe.exec(src)) !== null) {
        const v = parseMoney(m[1]);
        if (v !== null && v > 0 && v < 100000) candidates.push(v);
      }
      if (candidates.length) break; // preferir la misma línea
    }
  });
  // Con varias líneas "TOTAL", el total real suele ser el mayor
  let amount = candidates.length ? Math.max(...candidates) : null;

  // 2) Respaldo: el número con formato de dinero más grande de todo el recibo.
  if (amount === null) {
    let all = [];
    let m; moneyRe.lastIndex = 0;
    while ((m = moneyRe.exec(fullText)) !== null) {
      const v = parseMoney(m[1]);
      if (v !== null && v > 0 && v < 100000) all.push(v);
    }
    if (all.length) amount = Math.max(...all);
  }

  // ── Fecha ──
  let date = null;
  const dateRe = /\b(\d{1,2}[\/\-.]\d{1,2}[\/\-.](?:\d{4}|\d{2}))\b|\b((?:ene|feb|mar|abr|may|jun|jul|ago|sep|oct|nov|dic|jan|apr|aug|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b|\b(\d{1,2}\s+(?:de\s+)?(?:ene|feb|mar|abr|may|jun|jul|ago|sep|oct|nov|dic)[a-z]*\.?\s+(?:de\s+)?\d{4})\b/i;
  const dm = fullText.match(dateRe);
  if (dm) date = (dm[1] || dm[2] || dm[3] || "").trim();

  // ── Comercio ── (primera línea "de texto" del recibo)
  let merchant = null;
  for (const line of lines.slice(0, 6)) {
    const letters = (line.match(/[A-Za-zÁÉÍÓÚÑáéíóúñ]/g) || []).length;
    if (letters < 3) continue;                    // líneas de números/códigos
    if (/^\d/.test(line) && letters < 6) continue; // direcciones que inician en número
    if (/(recibo|receipt|invoice|factura|tel[:.]|www\.|http|order\s*#|ticket)/i.test(line)) continue;
    merchant = line.replace(/\s{2,}/g, " ").slice(0, 48);
    break;
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
