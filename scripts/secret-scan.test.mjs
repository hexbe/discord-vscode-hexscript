// Tests for secret-scan.mjs. Run: node --test scripts/secret-scan.test.mjs
//
// Every fake credential is assembled at runtime from fragments, so this file never contains a string that the scanner
// (or GitHub push protection) would flag, and the repo still scans clean.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { entropy, fingerprint, parseAllowList, redact, run, scanLine, sensitiveFileType } from "./secret-scan.mjs";

const j = (...parts) => parts.join("");
const rnd = (alphabet, n, seed = 7) => {
    // Deterministic pseudo-random string so the tests are stable and the "secret" has real entropy.
    let x = seed;
    let out = "";
    for (let i = 0; i < n; i++) {
        x = (x * 1103515245 + 12345) & 0x7fffffff;
        out += alphabet[(x >>> 8) % alphabet.length];
    }
    return out;
};
const B62 = j("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789");

const fakes = {
    aws: j("AK", "IA", rnd("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)),
    ghp: j("gh", "p_", rnd(B62, 36)),
    ghPat: j("github", "_pat_", rnd(B62, 22), "_", rnd(B62, 59)),
    discord: j("M", rnd(B62, 23), ".", rnd(B62, 6), ".", rnd(B62, 27)),
    cfNew: j("cf", "ut_", rnd(B62, 48)),
    slack: j("xo", "xb-", rnd("0123456789", 12), "-", rnd(B62, 24)),
    stripe: j("sk", "_live_", rnd(B62, 24)),
    google: j("AI", "za", rnd(B62 + "_-", 35)),
    npm: j("npm", "_", rnd(B62, 36)),
    jwt: j("ey", "J", rnd(B62, 20), ".ey", "J", rnd(B62, 24), ".", rnd(B62, 30)),
    keyHeader: j("-----BEGIN ", "RSA PRIVATE", " KEY-----"),
    random: rnd(B62 + "+/", 32, 99),
};

const types = (line) => scanLine(line).map((h) => h.type);

describe("scanLine", () => {
    it("finds a private key block", () => assert.deepEqual(types(fakes.keyHeader), ["private-key"]));
    it("finds an OpenSSH private key block", () =>
        assert.deepEqual(types(j("-----BEGIN ", "OPENSSH PRIVATE", " KEY-----")), ["private-key"]));
    it("finds AWS access keys", () => assert.deepEqual(types(`id: ${fakes.aws}`), ["aws-access-key"]));
    it("ignores the documented AWS example key", () =>
        assert.deepEqual(types(j("AK", "IA", "IOSFODNN7", "EXAMPLE")), []));
    it("finds GitHub tokens", () => {
        assert.deepEqual(types(`t=${fakes.ghp}`), ["github-token"]);
        assert.deepEqual(types(`t=${fakes.ghPat}`), ["github-token"]);
    });
    it("finds Discord bot tokens", () => assert.deepEqual(types(`"${fakes.discord}"`), ["discord-bot-token"]));
    it("finds Cloudflare tokens (prefixed and named)", () => {
        assert.deepEqual(types(fakes.cfNew), ["cloudflare-token"]);
        assert.deepEqual(types(j("CLOUDFLARE_API_", "TOKEN=", rnd(B62 + "_-", 40, 3))), ["cloudflare-token"]);
    });
    it("finds Slack tokens", () => assert.deepEqual(types(fakes.slack), ["slack-token"]));
    it("finds Stripe keys", () => assert.deepEqual(types(fakes.stripe), ["stripe-key"]));
    it("finds Google API keys", () => assert.deepEqual(types(`key=${fakes.google}`), ["google-api-key"]));
    it("finds npm tokens", () => assert.deepEqual(types(`//registry/:_authToken=${fakes.npm}`), ["npm-token"]));
    it("finds JWTs", () => assert.deepEqual(types(`Bearer ${fakes.jwt}`), ["jwt"]));

    it("finds a database URL with a real password", () => {
        const url = j("postgres", "://app:", fakes.random.replace(/[+/]/g, "x"), "@db.internal:5432/app");
        assert.deepEqual(types(url), ["url-password"]);
    });
    it("ignores database URLs with placeholder or default passwords", () => {
        assert.deepEqual(types(j("postgres", "://user:", "<password>", "@localhost/db")), []);
        assert.deepEqual(types(j("postgres", "://postgres:", "postgres", "@localhost/db")), []);
        assert.deepEqual(types(j("mysql", "://root:", "${DB_PASS}", "@db/app")), []);
        assert.deepEqual(types(j("redis", "://", "default:", "changeme", "@cache:6379")), []);
        assert.deepEqual(types(j("postgresql", "://svc:", "{pg_pass}", "@127.0.0.1:5432/db")), []);
        assert.deepEqual(types(String.raw`r"(postgresql://[^:\s]+:)[^@\s]+"`), []);
    });

    it("finds a high-entropy assignment", () => {
        assert.deepEqual(types(`const ${j("api", "Key")} = "${fakes.random}";`), ["generic-secret"]);
        assert.deepEqual(types(`${j("pass", "word")}: '${fakes.random}'`), ["generic-secret"]);
        assert.deepEqual(types(`"${j("client_", "secret")}": "${fakes.random}"`), ["generic-secret"]);
    });
    it("skips placeholders, env lookups and low-entropy values", () => {
        const name = j("pass", "word");
        for (const v of ["changeme-changeme-1", "<your-password-here-123>", "xxxxxxxxxxxxxxxxxxxx", "${DATABASE_PASSWORD_VALUE}", "aaaaaaaaaaaaaaaaaaaa"]) {
            assert.deepEqual(types(`${name} = "${v}"`), [], v);
        }
        assert.deepEqual(types(`${name} = process.env.DB_PASSWORD`), []);
        assert.deepEqual(types(`${j("to", "ken")} = os.environ["TOKEN"]`), []);
    });
    it("skips identifiers, paths, plain URLs and UUIDs", () => {
        const t = j("to", "ken");
        assert.deepEqual(types(`${t}Key = "getAuthenticationTokenFromStorage"`), []);
        assert.deepEqual(types(`${t}Url = "https://api.example.org/v1/auth/${t}s"`), []);
        assert.deepEqual(types(`${t}File = "/var/lib/app/some/long/path/to/file"`), []);
        assert.deepEqual(types(`${t} = "123e4567-e89b-12d3-a456-426614174000"`), []);
    });
    it("does not flag ordinary code", () => {
        assert.deepEqual(types("function getToken(user) { return user.token; }"), []);
        assert.deepEqual(types("const passwordMinLength = 12;"), []);
    });
});

describe("helpers", () => {
    it("redacts to the first four characters", () => assert.equal(redact("abcdefghij"), "abcd***"));
    it("fingerprints are stable and do not contain the secret", () => {
        const fp = fingerprint("x", "supersecretvalue");
        assert.equal(fp, fingerprint("x", "supersecretvalue"));
        assert.notEqual(fp, fingerprint("y", "supersecretvalue"));
        assert.match(fp, /^[0-9a-f]{16}$/);
    });
    it("computes Shannon entropy", () => {
        assert.equal(entropy("aaaa"), 0);
        assert.equal(entropy("abab"), 1);
    });
    it("recognises sensitive file names", () => {
        for (const f of [".env", "app/.env.production", "certs/server.pem", "a/b.key", "id_rsa", ".ssh/id_ed25519", "release.jks", "vps/secrets/server.env"]) {
            assert.ok(sensitiveFileType(f), f);
        }
        for (const f in { ".env.example": 1, "id_rsa.pub": 1, "src/environment.ts": 1, "keyboard.ts": 1, "id_map.ts": 1 }) {
            assert.equal(sensitiveFileType(f), null, f);
        }
    });
    it("parses the allow list and demands a reason", () => {
        const ok = parseAllowList("# comment\n\npath test/fixtures/** -- fake data\nfp 0123456789abcdef -- docs example\n");
        assert.equal(ok.errors.length, 0);
        assert.equal(ok.paths.length, 1);
        assert.ok(ok.paths[0].re.test("test/fixtures/a/b.json"));
        assert.ok(!ok.paths[0].re.test("src/a.json"));
        assert.equal(ok.fps.length, 1);
        assert.equal(parseAllowList("path src/**\n").errors.length, 1);
        assert.equal(parseAllowList("fp abcdef --  \n").errors.length, 1);
        assert.ok(parseAllowList("path *.fixture.json -- x").paths[0].re.test("deep/dir/a.fixture.json"));
    });
});

// ---------------------------------------------------------------------------------------------------------------
// End to end against throwaway git repositories

const tmpRoot = mkdtempSync(join(tmpdir(), "secret-scan-test-"));
after(() => rmSync(tmpRoot, { recursive: true, force: true }));

function makeRepo(name) {
    const dir = join(tmpRoot, name);
    mkdirSync(dir, { recursive: true });
    const g = (...args) => execFileSync("git", args, { cwd: dir, stdio: ["ignore", "pipe", "pipe"] }).toString();
    g("init", "-q", "-b", "main");
    g("config", "user.email", "t@example.invalid");
    g("config", "user.name", "t");
    g("config", "commit.gpgsign", "false");
    const write = (rel, text) => {
        const abs = join(dir, rel);
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, text);
    };
    return { dir, g, write };
}

async function scan(dir, ...argv) {
    let out = "";
    let err = "";
    const code = await run([...argv, "--cwd", dir], { stdout: { write: (s) => { out += s; } }, stderr: { write: (s) => { err += s; } } });
    return { code, out, err };
}

describe("cli", () => {
    it("--staged reports type, file, line and a redacted preview, never the secret", async () => {
        const { dir, g, write } = makeRepo("staged");
        write("README.md", "hello\n");
        g("add", "."); g("commit", "-qm", "init");
        write("src/config.js", `// one\nconst x = 1;\nconst token = "${fakes.ghp}";\n`);
        g("add", "src/config.js");
        const r = await scan(dir, "--staged");
        assert.equal(r.code, 1);
        assert.match(r.out, /\[github-token\] src\/config\.js:3 preview="ghp_\*\*\*" fp=[0-9a-f]{16}/);
        assert.ok(!r.out.includes(fakes.ghp) && !r.err.includes(fakes.ghp));
        assert.ok(!r.out.includes(fakes.ghp.slice(0, 8)));
    });

    it("--staged is clean for harmless changes and ignores unstaged files", async () => {
        const { dir, g, write } = makeRepo("clean");
        write("a.txt", "one\n");
        g("add", "."); g("commit", "-qm", "init");
        write("b.txt", `${fakes.aws}\n`); // not staged
        write("a.txt", "two\n");
        g("add", "a.txt");
        const r = await scan(dir, "--staged");
        assert.equal(r.code, 0, r.out + r.err);
    });

    it("flags staged .env, .pem and binary key files by name", async () => {
        const { dir, g, write } = makeRepo("names");
        write("seed.txt", "x\n"); g("add", "."); g("commit", "-qm", "init");
        write(".env", "A=1\n");
        write("certs/server.pem", "not really a key\n");
        write("android/release.jks", "\u0000\u0001\u0002binary");
        write(".env.example", "A=\n");
        g("add", ".");
        const r = await scan(dir, "--staged");
        assert.equal(r.code, 1);
        assert.match(r.out, /\[env-file\] \.env /);
        assert.match(r.out, /\[private-key-file\] certs\/server\.pem /);
        assert.match(r.out, /\[private-key-file\] android\/release\.jks /);
        assert.ok(!r.out.includes(".env.example"));
    });

    it("--range scans every commit in the range, even if a later commit removes the secret", async () => {
        const { dir, g, write } = makeRepo("range");
        write("a.txt", "base\n"); g("add", "."); g("commit", "-qm", "base");
        g("checkout", "-q", "-b", "feature");
        write("conf.js", `const k = "${fakes.google}";\n`); g("add", "."); g("commit", "-qm", "add key");
        write("conf.js", "const k = process.env.K;\n"); g("add", "."); g("commit", "-qm", "remove key");
        const r = await scan(dir, "--range", "main...HEAD");
        assert.equal(r.code, 1);
        assert.match(r.out, /\[google-api-key\] conf\.js:1 commit=[0-9a-f]{7} preview="AIza\*\*\*"/);
        const clean = await scan(dir, "--range", "main..main");
        assert.equal(clean.code, 0);
    });

    it("--history finds a secret that is long gone from the tree, --tree does not", async () => {
        const { dir, g, write } = makeRepo("history");
        write("old.js", `const n = "${fakes.npm}";\n`); g("add", "."); g("commit", "-qm", "oops");
        write("old.js", "const n = 1;\n"); g("add", "."); g("commit", "-qm", "fix");
        assert.equal((await scan(dir, "--history")).code, 1);
        assert.equal((await scan(dir, "--tree")).code, 0);
    });

    it("an added line that starts with +++ is still scanned", async () => {
        const { dir, g, write } = makeRepo("plusplus");
        write("a.txt", "x\n"); g("add", "."); g("commit", "-qm", "init");
        write("a.txt", `x\n++ ${fakes.aws}\n`); g("add", ".");
        const r = await scan(dir, "--staged");
        assert.equal(r.code, 1);
        assert.match(r.out, /\[aws-access-key\] a\.txt:2/);
    });

    it("the allow list silences by path and by fingerprint, and rejects entries without a reason", async () => {
        const { dir, g, write } = makeRepo("allow");
        write("seed.txt", "x\n"); g("add", "."); g("commit", "-qm", "init");
        write("test/fixtures/a.json", `{"k":"${fakes.stripe}"}\n`);
        write("src/b.js", `const s = "${fakes.slack}";\n`);
        g("add", ".");
        const before = await scan(dir, "--staged");
        assert.equal(before.code, 1);
        const fp = before.out.match(/\[slack-token\] src\/b\.js:1 .*fp=([0-9a-f]{16})/)[1];
        write(".secret-scan-allow", `path test/fixtures/** -- fake stripe fixture\nfp ${fp} -- documented example\n`);
        const after1 = await scan(dir, "--staged");
        assert.equal(after1.code, 0, after1.out + after1.err);
        assert.match(after1.out, /2 allow-listed/);
        write(".secret-scan-allow", "path test/fixtures/**\n");
        assert.equal((await scan(dir, "--staged")).code, 2);
    });

    it("skips lockfiles and reports usage errors with exit 2", async () => {
        const { dir, g, write } = makeRepo("misc");
        write("seed.txt", "x\n"); g("add", "."); g("commit", "-qm", "init");
        write("package-lock.json", `{"integrity":"${j("pass", "word")}: \\"${fakes.random}\\""}\n`);
        g("add", ".");
        assert.equal((await scan(dir, "--staged")).code, 0);
        assert.equal((await scan(dir)).code, 2);
        assert.equal((await scan(dir, "--range")).code, 2);
        assert.equal((await scan(dir, "--bogus")).code, 2);
        assert.equal((await scan(dir, "--range", "nope..HEAD")).code, 2);
    });
});
