let userIP; // Variável para armazenar o IP

fetch("https://api64.ipify.org?format=json")
  .then(response => response.json())
  .then(data => {
    userIP = data.ip;
  })
async function hashIP(ip) {
    const encoder = new TextEncoder();
    const data = encoder.encode(ip);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

hashIP(userIP);

//Test

const express = require("express");
const rateLimit = require("express-rate-limit");
const ipFilter = require("express-ip-filter").IpFilter;

const app = express();

// Lista de IPs bloqueados
const blockedIPs = ["192.168.1.1", "203.0.113.45"]; // Exemplo de IPs bloqueados

// Configuração de Limitação de Requisições
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutos
    max: 50, // Máximo de 50 requisições por IP
    message: "Muitas requisições. Tente novamente mais tarde."
});

// Middleware para bloquear IPs suspeitos
app.use(ipFilter(blockedIPs, { mode: "deny" }));

// Limitar o número de requisições
app.use(limiter);

// Proteção contra XSS (para simplificação, aqui só escapamos caracteres especiais)
function sanitizeInput(input) {
    return input.replace(/[<>"'&]/g, (match) => {
        const escape = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
            "&": "&amp;"
        };
        return escape[match];
    });
}

app.use((req, res, next) => {
    // Sanitizar inputs para prevenir XSS
    if (req.body) {
        for (let key in req.body) {
            req.body[key] = sanitizeInput(req.body[key]);
        }
    }
    next();
});

// Exemplo de rota
app.get("/", (req, res) => {
    res.send("Bem-vindo ao site protegido por firewall!");
});

app.listen(3000, () => {
    console.log("Servidor rodando na porta 3000");
});
