// Cloudflare Email Worker — receives mail via Email Routing catch-all,
// extracts a 6-digit OTP, stores it in KV keyed by recipient address.
//
// Bindings (set by setup_cf_email_worker.py):
//   OTP_KV       — KV namespace for {recipient → {otp, ts, from, subject}}
//   FALLBACK_TO  — (optional) plain_text. If set, forward raw email to this
//                  address as well (useful during migration off IMAP/QQ).
//
// Pipeline reads KV via CF API (CTF-reg/cf_kv_otp_provider.py).

export default {
  async email(message, env, ctx) {
    const to = (message.to || '').toLowerCase();
    const from = message.from || '';

    // Read the raw RFC822 message into a string
    let raw = '';
    try {
      const reader = message.raw.getReader();
      const decoder = new TextDecoder('utf-8', { fatal: false });
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        raw += decoder.decode(value, { stream: true });
      }
      raw += decoder.decode();
    } catch (e) {
      console.error('raw read failed:', e && e.message);
    }

    // Pull the Subject header out for fast-path matching (most OpenAI OTP
    // mails put the code right in the subject)
    const subjMatch = raw.match(/^Subject:\s*(.+?)(?:\r?\n[^\s])/ms);
    const subject = subjMatch ? subjMatch[1].trim().slice(0, 200) : '';

    // OTP extraction — semantic context first to avoid grabbing tracking ids
    let otp = null;
    const candidates = [
      // "code is 123456", "verification code: 123456", etc.
      /(?:code(?:\s*is)?|verification|one[-\s]*time|verify|验证码)[^\d]{0,40}(\d{6})\b/i,
      // ChatGPT subject template: "Your ChatGPT code is 123456"
      /chatgpt[^\d]{0,40}(\d{6})/i,
      /openai[^\d]{0,40}(\d{6})/i,
    ];
    for (const re of candidates) {
      const m = (subject + '\n' + raw).match(re);
      if (m) { otp = m[1]; break; }
    }
    if (!otp) {
      const m = raw.match(/\b(\d{6})\b/);
      if (m) otp = m[1];
    }

    if (otp && to) {
      const payload = JSON.stringify({
        otp,
        ts: Date.now(),
        from,
        subject,
      });
      try {
        await env.OTP_KV.put(to, payload, { expirationTtl: 600 });
        console.log(`stored OTP for ${to.slice(0, 40)} (subject="${subject.slice(0, 60)}")`);
      } catch (e) {
        console.error('KV put failed:', e && e.message);
      }
    } else {
      console.log(`no OTP extracted to=${to.slice(0, 40)} subject="${subject.slice(0, 60)}"`);
    }

    // Optional: forward raw email to fallback mailbox (e.g. existing QQ inbox)
    // Useful during the IMAP→KV migration to keep both paths warm.
    if (env.FALLBACK_TO) {
      try {
        await message.forward(env.FALLBACK_TO);
      } catch (e) {
        console.error('forward failed:', e && e.message);
      }
    }
  },
};
