#!/usr/bin/env node
// Dependency-free secret scanner. Plain Node ESM, no npm packages, only `git` on PATH.
//
// Canonical copy: hexbe-game/scripts/secret-scan.mjs. The same file is vendored unchanged into the other hexbe repos;
// change it in hexbe-game first and copy it over (the tests in secret-scan.test.mjs travel with it).
//
//   node scripts/secret-scan.mjs --staged                      staged diff (the pre-commit hook)
//   node scripts/secret-scan.mjs --range origin/main...HEAD    every commit in a git range (CI)
//   node scripts/secret-scan.mjs --tree                        tracked files in the working tree
//   node scripts/secret-scan.mjs --history                     every commit on every ref
//
// It never prints a secret: only the type, file, line number, a redacted preview (first 4 characters + ***) and a
// one-way fingerprint that can be pasted into .secret-scan-allow. Exit 0 = clean, 1 = findings, 2 = usage or git error.
//
// Allow list (.secret-scan-allow at the repo root), one entry per line, a reason is mandatory:
//   path <glob> -- <reason>          silence every finding in matching files (no "/" in the glob = match any basename)
//   fp <fingerprint> -- <reason>     silence one exact secret wherever it appears
// Lines starting with # and blank lines are ignored.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const MAX_LINE = 20000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

// Files whose content is machine generated hashes, not secrets.
const SKIP_PATH = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|composer\.lock|Podfile\.lock|go\.sum)$/;

// ---------------------------------------------------------------------------------------------------------------
// Rules

/** Words that mark a value as a placeholder rather than a real secret. */
const PLACEHOLDER =
    /changeme|change[-_ ]?me|your[-_ ]|example|placeholder|dummy|sample|fake|redacted|replace|todo|secret[-_ ]?here|insert|x{4,}|\*{4,}|\.\.\.|0{7,}|<[^>]*>|\$\{|\{\{|%[sd]\b|%\(|process\.env|os\.environ|getenv|\bENV\[/i;

/** Passwords that are not worth flagging inside a connection string (documentation and local dev defaults). */
const WEAK_PASSWORDS = new Set([
    "password", "passwd", "pass", "postgres", "root", "admin", "secret", "user", "test", "guest", "mysql", "redis",
    "mongo", "docker", "changeme", "example", "letmein", "123456", "qwerty",
]);

/** Specific token formats. `min` is a floor on the Shannon entropy of the matched secret (0 = no check). */
const RULES = [
    { type: "private-key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |PRIVATE )?(?:PRIVATE KEY(?: BLOCK)?)-----/g, whole: true },
    { type: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { type: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
    { type: "github-token", re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
    { type: "discord-bot-token", re: /\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b/g, min: 3.5 },
    { type: "discord-webhook", re: /discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/([A-Za-z0-9_-]{50,})/g, group: 1 },
    { type: "cloudflare-token", re: /\bcf(?:ut|at|k)_[A-Za-z0-9]{40,}\b/g },
    {
        type: "cloudflare-token",
        // Legacy Cloudflare API tokens (40 chars) and global keys (37 hex) have no prefix: require the name.
        re: /(?:cloudflare|\bcf)[A-Za-z0-9_.-]{0,20}?(?:api[_-]?)?(?:token|key)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{37,40})\b/gi,
        group: 1,
        min: 3.5,
    },
    { type: "slack-token", re: /\bxox[abeprs]-[A-Za-z0-9-]{10,}\b/g },
    { type: "slack-token", re: /\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+\b/g },
    { type: "slack-webhook", re: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/([A-Za-z0-9]{20,})/g, group: 1 },
    { type: "stripe-key", re: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
    { type: "stripe-key", re: /\bwhsec_[A-Za-z0-9]{24,}\b/g },
    { type: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { type: "google-oauth-secret", re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g },
    { type: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}/g },
];

/** `scheme://user:password@host` with a real-looking password. */
const URL_PASSWORD = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|ftps?|https?):\/\/[^\s:/@'"`]+:([^\s@'"`/]{3,})@/gi;

/** `password = "<value>"`, `"apiKey": "<value>"`, `secret: '<value>'` ... */
const ASSIGNMENT =
    /[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*["']?\s*(?::=|=>|[:=])\s*["'`]([^"'`\s]{16,})["'`]/gi;

const SENSITIVE_FILES = [
    { type: "env-file", test: (base) => /^\.env(\..+)?$|\.env$/.test(base) && !/\.(example|sample|template|dist|defaults?)$/.test(base) },
    { type: "private-key-file", test: (base) => /\.(pem|key|p12|pfx|jks|keystore)$/i.test(base) },
    { type: "private-key-file", test: (base) => /^id_(rsa|dsa|ecdsa|ed25519)(_.*)?$/.test(base) && !/\.pub$/.test(base) },
];

// ---------------------------------------------------------------------------------------------------------------
// Helpers

export function entropy(s) {
    if (!s) return 0;
    const counts = new Map();
    for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
    let h = 0;
    for (const n of counts.values()) {
        const p = n / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}

export function redact(secret) {
    return `${secret.slice(0, 4)}***`;
}

export function fingerprint(type, secret) {
    return createHash("sha256").update(`${type}\0${secret}`).digest("hex").slice(0, 16);
}

function looksPlaceholder(v) {
    return PLACEHOLDER.test(v) || /^(.)\1+$/.test(v);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function plausibleAssignmentValue(v) {
    if (looksPlaceholder(v)) return false;
    if (UUID.test(v) || /^sha\d+-/.test(v)) return false;
    if (/^[./~\\]/.test(v) || /^[a-z]+:\/\/[^@]*$/i.test(v)) return false; // paths and plain URLs
    const h = entropy(v);
    if (h < 3.5) return false;
    // Identifiers and sentences are not secrets: need a digit, or be long and very random.
    return /\d/.test(v) || (v.length >= 24 && h >= 4.0);
}

function globToRegExp(glob) {
    let g = glob.replace(/\\/g, "/");
    if (!g.includes("/")) g = `**/${g}`;
    let re = "";
    for (let i = 0; i < g.length; i++) {
        const c = g[i];
        if (c === "*") {
            if (g[i + 1] === "*") {
                i++;
                if (g[i + 1] === "/") { i++; re += "(?:.*/)?"; } else re += ".*";
            } else re += "[^/]*";
        } else if (c === "?") re += "[^/]";
        else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
    return new RegExp(`^${re}$`);
}

export function parseAllowList(text) {
    const paths = [];
    const fps = [];
    const errors = [];
    text.split(/\r?\n/).forEach((raw, i) => {
        const line = raw.trim();
        if (!line || line.startsWith("#")) return;
        const m = line.match(/^(path|fp)\s+(\S+)\s+--\s+(\S.*)$/);
        if (!m) {
            errors.push(`.secret-scan-allow:${i + 1}: expected "path <glob> -- <reason>" or "fp <fingerprint> -- <reason>"`);
            return;
        }
        if (m[1] === "path") paths.push({ glob: m[2], re: globToRegExp(m[2]), reason: m[3] });
        else fps.push({ fp: m[2].toLowerCase(), reason: m[3] });
    });
    return { paths, fps, errors };
}

const EMPTY_ALLOW = { paths: [], fps: [], errors: [] };

function isAllowed(allow, file, fp) {
    if (allow.paths.some((p) => p.re.test(file))) return true;
    return allow.fps.some((a) => a.fp.length >= 12 && fp.startsWith(a.fp));
}

/**
 * Scan one line. Returns [{ type, secret }] (the secret stays inside the process; callers print redact(secret)).
 */
export function scanLine(line) {
    if (line.length > MAX_LINE) line = line.slice(0, MAX_LINE);
    const hits = [];
    const seen = new Set();
    const add = (type, secret) => {
        const key = `${type}\0${secret}`;
        if (seen.has(key)) return;
        seen.add(key);
        hits.push({ type, secret });
    };

    for (const rule of RULES) {
        rule.re.lastIndex = 0;
        for (const m of line.matchAll(rule.re)) {
            const secret = rule.whole ? m[0] : m[rule.group || 0];
            if (!secret) continue;
            if (!rule.whole && (/example/i.test(secret) || /^(.)\1+$/.test(secret) || /x{6,}/i.test(secret))) continue;
            if (rule.min && entropy(secret) < rule.min) continue;
            add(rule.type, secret);
        }
    }

    URL_PASSWORD.lastIndex = 0;
    for (const m of line.matchAll(URL_PASSWORD)) {
        const pw = m[1];
        if (WEAK_PASSWORDS.has(pw.toLowerCase()) || looksPlaceholder(pw)) continue;
        if (/^[{[(\\<$%@]/.test(pw) || /[\]\\]/.test(pw)) continue; // template syntax and regex fragments, not a password
        add("url-password", pw);
    }

    ASSIGNMENT.lastIndex = 0;
    for (const m of line.matchAll(ASSIGNMENT)) {
        if (plausibleAssignmentValue(m[1])) add("generic-secret", m[1]);
    }
    return hits;
}

export function sensitiveFileType(file) {
    const base = file.split("/").pop();
    for (const r of SENSITIVE_FILES) if (r.test(base)) return r.type;
    return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Diff / tree walking

function git(args, { cwd } = {}) {
    return spawn("git", ["-c", "core.quotepath=off", ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] });
}

/** Run git and call onLine for every stdout line. Resolves with the exit code. */
function gitLines(args, onLine, opts) {
    return new Promise((resolve, reject) => {
        const child = git(args, opts);
        let stderr = "";
        child.stderr.on("data", (d) => { stderr += d; });
        child.on("error", reject);
        const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
        rl.on("line", onLine);
        child.on("close", (code) => {
            if (code !== 0) reject(new Error(`git ${args.join(" ")} failed (${code}): ${stderr.trim()}`));
            else resolve(code);
        });
    });
}

function gitText(args, opts) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const child = git(args, opts);
        let stderr = "";
        child.stdout.on("data", (d) => chunks.push(d));
        child.stderr.on("data", (d) => { stderr += d; });
        child.on("error", reject);
        child.on("close", (code) => {
            if (code !== 0) reject(new Error(`git ${args.join(" ")} failed (${code}): ${stderr.trim()}`));
            else resolve(Buffer.concat(chunks).toString("utf8"));
        });
    });
}

/**
 * Parse `git diff` / `git log -p` output (with -U0) and report findings. `emit` receives
 * { type, file, line, secret, commit }.
 */
function makeDiffParser(emit) {
    let commit = "";
    let file = null;
    let skip = false;
    let newLine = 0;
    let inHeader = false;
    return (raw) => {
        if (raw.startsWith("secret-scan-commit:")) { commit = raw.slice("secret-scan-commit:".length).slice(0, 7); file = null; inHeader = false; return; }
        if (raw.startsWith("diff --git ")) {
            // Binary files (keystores, .pem) have no +++ line, so the sensitive-name check lives here.
            file = null;
            skip = false;
            inHeader = true;
            const m = raw.match(/ b\/(.+)$/);
            const path = m ? m[1] : null;
            const type = path && sensitiveFileType(path);
            if (type) emit({ type, file: path, line: 0, secret: path, commit });
            return;
        }
        if (inHeader) {
            // Header lines only exist before the first hunk; afterwards a content line may legitimately start with "+++".
            if (raw.startsWith("+++ ")) {
                const p = raw.slice(4);
                if (p === "/dev/null") { file = null; return; }
                file = p.replace(/^b\//, "").replace(/\t.*$/, "");
                skip = SKIP_PATH.test(file);
            } else if (raw.startsWith("@@")) {
                inHeader = false;
            } else return;
        }
        if (raw.startsWith("@@")) {
            const m = raw.match(/\+(\d+)/);
            newLine = m ? Number(m[1]) : 0;
            return;
        }
        if (file === null || skip) return;
        if (raw.startsWith("+") && !inHeader) {
            const text = raw.slice(1);
            for (const hit of scanLine(text)) emit({ ...hit, file, line: newLine, commit });
            newLine++;
        }
    };
}

async function scanTree(emit, cwd) {
    const out = await gitText(["ls-files", "-z"], { cwd });
    for (const file of out.split("\0").filter(Boolean)) {
        if (SKIP_PATH.test(file)) continue;
        const type = sensitiveFileType(file);
        if (type) emit({ type, file, line: 0, secret: file, commit: "" });
        let buf;
        try {
            const abs = cwd ? `${cwd}/${file}` : file;
            if (statSync(abs).size > MAX_FILE_BYTES) continue;
            buf = readFileSync(abs);
        } catch { continue; }
        if (buf.subarray(0, 8000).includes(0)) continue;
        buf.toString("utf8").split(/\r?\n/).forEach((text, i) => {
            for (const hit of scanLine(text)) emit({ ...hit, file, line: i + 1, commit: "" });
        });
    }
}

// ---------------------------------------------------------------------------------------------------------------
// CLI

const USAGE = `usage: secret-scan.mjs (--staged | --range <git-range> | --tree | --history) [--allow <file>] [--cwd <dir>]`;

export async function run(argv, { stdout = process.stdout, stderr = process.stderr } = {}) {
    const args = { mode: null, range: null, allow: ".secret-scan-allow", cwd: undefined };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === "--staged") args.mode = "staged";
        else if (a === "--tree") args.mode = "tree";
        else if (a === "--history") args.mode = "history";
        else if (a === "--range") { args.mode = "range"; args.range = argv[++i]; }
        else if (a === "--allow") args.allow = argv[++i];
        else if (a === "--cwd") args.cwd = argv[++i];
        else if (a === "-h" || a === "--help") { stdout.write(`${USAGE}\n`); return 0; }
        else { stderr.write(`secret-scan: unknown argument ${a}\n${USAGE}\n`); return 2; }
    }
    if (!args.mode || (args.mode === "range" && !args.range)) { stderr.write(`${USAGE}\n`); return 2; }

    const cwd = args.cwd;
    let allow = EMPTY_ALLOW;
    const allowPath = cwd ? `${cwd}/${args.allow}` : args.allow;
    if (existsSync(allowPath)) {
        allow = parseAllowList(readFileSync(allowPath, "utf8"));
        if (allow.errors.length) { for (const e of allow.errors) stderr.write(`secret-scan: ${e}\n`); return 2; }
    }

    const findings = [];
    const seen = new Set();
    let allowed = 0;
    const emit = (f) => {
        const fp = fingerprint(f.type, f.secret);
        if (isAllowed(allow, f.file, fp)) { allowed++; return; }
        // The same secret on the same path is reported once (the oldest commit wins in --history).
        const key = `${f.file}\0${fp}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({ ...f, fp });
    };

    try {
        if (args.mode === "tree") {
            await scanTree(emit, cwd);
        } else {
            const parse = makeDiffParser(emit);
            const diffOpts = ["-U0", "--no-color", "--no-ext-diff", "--no-renames", "--diff-filter=ACMR"];
            if (args.mode === "staged") {
                await gitLines(["diff", "--cached", ...diffOpts], parse, { cwd });
            } else {
                // "A...B" would also pull in commits that only exist on A; a scan wants what B adds on top of A.
                const range = args.mode === "history" ? ["--all"] : [args.range.replace("...", "..")];
                await gitLines(
                    ["log", "-p", "--reverse", "--no-merges", "--format=secret-scan-commit:%H", ...diffOpts, ...range, "--"],
                    parse,
                    { cwd },
                );
            }
        }
    } catch (err) {
        stderr.write(`secret-scan: ${err.message}\n`);
        return 2;
    }

    for (const f of findings) {
        const where = f.line ? `${f.file}:${f.line}` : f.file;
        const at = f.commit ? ` commit=${f.commit}` : "";
        const preview = f.line ? ` preview="${redact(f.secret)}"` : "";
        stdout.write(`secret-scan: [${f.type}] ${where}${at}${preview} fp=${f.fp}\n`);
    }
    if (findings.length) {
        stderr.write(
            `secret-scan: ${findings.length} possible secret(s) found (${allowed} allow-listed). ` +
                `If a hit is a false positive, add "fp <fingerprint> -- <reason>" or "path <glob> -- <reason>" to .secret-scan-allow. ` +
                `If it is real, remove it and rotate it.\n`,
        );
        return 1;
    }
    stdout.write(`secret-scan: clean (${args.mode}${args.range ? ` ${args.range}` : ""}, ${allowed} allow-listed)\n`);
    return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    run(process.argv.slice(2)).then((code) => process.exit(code));
}
