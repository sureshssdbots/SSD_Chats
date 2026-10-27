# SecureChat (Supabase)

End-to-end encrypted chat. RSA-OAEP 3072 + AES-256-GCM + ECDSA P-256 signatures.
Server sirf ciphertext dekhta hai. Private keys sirf user ke device par, passphrase se locked.

## Setup
1. Supabase > SQL Editor: `schema.sql` paste karke Run.
2. Authentication > Providers > Email: testing ke liye "Confirm email" band kar sakte ho.
3. Project Settings > API se Project URL aur **anon public** key `config.js` mein daalo.
   `service_role` key kabhi repo ya browser mein mat daalo.
4. Authentication > URL Configuration: Site URL = apni deployed site ka link.
5. Deploy: Cloudflare Pages ya Netlify (private repo chalta hai). Local test: `npx serve .`

## Security checklist
- GitHub aur Supabase account par 2-step verification lagao.
- `supabase-js` ko CDN ke bajaye repo mein copy (vendor) karo aur `index.html` mein local path do.
- `_headers` (CSP) deploy mein active rahe. GitHub Pages par `_headers` nahi chalta, wahan sirf meta CSP lagti hai.
- Naye users ka fingerprint / safety number call par match karo.
- Free plan ka project kuch din inactive rehne par pause ho jaata hai.

## Limits
Forward secrecy, group chat, files, typing indicator, read receipts abhi nahi hain.
Server ko metadata dikhta hai (kaun kisko, kab). Sirf sender aur recipient apni rows padh sakte hain.
