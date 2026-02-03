// app.js — exemplo de mitigação de XSS em Express (Node.js)
import express from 'express';
import helmet from 'helmet';
import xss from 'xss'; // biblioteca simples para sanitização adicional (opcional)

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// 1) Security headers (CSP inclusive) — mitiga XSS baseado em script
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"], // adicione nonces/hashes conforme necessário
        "object-src": ["'none'"],
      },
    },
    xssFilter: false, // X-XSS-Protection é legado; CSP é o mecanismo moderno
  })
);

// 2) Escape/encode de saída — NUNCA renderize input bruto em HTML
const htmlEscape = (str = '') =>
  String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

// 3) Endpoint “eco” seguro
app.post('/echo', (req, res) => {
  // Validação + sanitização defensiva
  const userInput = typeof req.body.message === 'string' ? req.body.message : '';
  const sanitized = htmlEscape(userInput); // ou xss(userInput)

  // Renderização segura
  res.type('html').send(`
    <h1>Echo</h1>
    <p>Você disse: <span>${sanitized}</span></p>
  `);
});

// Inicialização
app.listen(3000, () => console.log('Safe app on http://localhost:3000'));
