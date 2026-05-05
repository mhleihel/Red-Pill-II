#!/usr/bin/env node
/**
 * Booyah Playwright crawler for Magento.
 *
 * Authenticates to Magento frontend and admin, visits every route from routes.json,
 * injects tagged probe values into all input fields, and logs:
 *   - Probe values that appear reflected in responses (DOM XSS candidates)
 *   - Network responses (for server-side reflection)
 *   - Console errors (potential XSS indicators)
 *
 * Usage:
 *   node playwright_crawl.js --routes routes.json --base-url http://localhost:8082
 *                            --admin-url http://localhost:8082/admin
 *                            --admin-user admin --admin-pass Admin123!
 *                            --output results/playwright_reflected.json
 *
 * Probes use format: booyah_PROBE_<paramName>_<id>
 * These are NOT XSS payloads — they are tagged values to detect reflection.
 * ZAP handles actual XSS payload injection.
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// Parse CLI args
const args = {};
process.argv.slice(2).forEach((arg, i, arr) => {
    if (arg.startsWith('--')) {
        const key = arg.slice(2);
        args[key] = arr[i + 1] && !arr[i + 1].startsWith('--') ? arr[i + 1] : true;
    }
});

const ROUTES_FILE = args['routes'] || 'routes.json';
const BASE_URL = (args['base-url'] || 'http://localhost:8082').replace(/\/$/, '');
const ADMIN_URL = args['admin-url'] || `${BASE_URL}/admin`;
const ADMIN_USER = args['admin-user'] || 'admin';
const ADMIN_PASS = args['admin-pass'] || 'Admin123!';
const OUTPUT_FILE = args['output'] || 'results/playwright_reflected.json';
const MAX_URLS = parseInt(args['max-urls'] || '500', 10);
const TIMEOUT_MS = parseInt(args['timeout'] || '15000', 10);

const routes = JSON.parse(fs.readFileSync(ROUTES_FILE, 'utf-8'));
const findings = [];

function makeProbe(paramName, id) {
    return `booyahP${id}_${paramName.slice(0, 8)}`;
}

async function crawlFrontend(page, frontendRoutes) {
    let count = 0;
    for (const route of frontendRoutes) {
        if (count >= MAX_URLS) break;
        const url = BASE_URL + route.url.replace(/<unmatched>/g, '');
        if (!url || url.includes('<')) continue;

        try {
            const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT_MS });
            const body = await page.content();
            const probeId = count;

            // Check for probe reflection (from previous visits)
            const reflectedProbes = findings
                .filter(f => f.type === 'probe_sent' && body.includes(f.probe))
                .map(f => f.probe);

            if (reflectedProbes.length > 0) {
                findings.push({
                    type: 'probe_reflected',
                    url,
                    reflected_probes: reflectedProbes,
                    status: resp?.status(),
                });
                console.log(`[!] REFLECTION at ${url}: ${reflectedProbes.join(', ')}`);
            }

            // Fill forms with probe values
            const inputs = await page.$$('input[type="text"], input[type="search"], input:not([type]), textarea');
            for (const input of inputs.slice(0, 5)) {
                try {
                    const name = await input.getAttribute('name') || 'unknown';
                    const probe = makeProbe(name, probeId);
                    await input.fill(probe, { timeout: 2000 });
                    findings.push({ type: 'probe_sent', url, probe, param: name });
                } catch (_) { /* input not interactable */ }
            }

            // Submit forms with probes
            const forms = await page.$$('form');
            for (const form of forms.slice(0, 2)) {
                try {
                    await form.evaluate(f => f.submit());
                    await page.waitForLoadState('domcontentloaded', { timeout: 5000 });
                    const newBody = await page.content();

                    const reflected = findings
                        .filter(f => f.type === 'probe_sent' && f.url === url && newBody.includes(f.probe));
                    if (reflected.length > 0) {
                        findings.push({
                            type: 'form_reflection',
                            source_url: url,
                            current_url: page.url(),
                            reflected_probes: reflected.map(f => f.probe),
                        });
                        console.log(`[!] FORM REFLECTION from ${url} -> ${page.url()}`);
                    }
                    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT_MS });
                } catch (_) { /* form submit failed */ }
            }

            count++;
            if (count % 50 === 0) {
                process.stderr.write(`  Crawled ${count} frontend URLs\n`);
            }
        } catch (e) {
            // Navigation errors are expected for unavailable routes
            if (!e.message.includes('net::ERR') && !e.message.includes('Timeout')) {
                console.error(`  Error crawling ${url}: ${e.message.slice(0, 100)}`);
            }
        }
    }
    process.stderr.write(`[+] Frontend crawl: ${count} URLs visited\n`);
}

async function authenticateAdmin(page) {
    try {
        await page.goto(ADMIN_URL, { waitUntil: 'domcontentloaded', timeout: 20000 });
        await page.fill('#username', ADMIN_USER);
        await page.fill('#login', ADMIN_PASS);
        await page.click('.action-login');
        await page.waitForURL(/admin.*dashboard|admin.*index/, { timeout: 15000 });
        console.log('[+] Admin authenticated');
        return true;
    } catch (e) {
        console.error(`  Admin auth failed: ${e.message.slice(0, 100)}`);
        return false;
    }
}

async function crawlAdmin(page, adminRoutes) {
    let count = 0;
    for (const route of adminRoutes) {
        if (count >= Math.min(MAX_URLS, 100)) break;
        const url = BASE_URL + route.url.replace(/<unmatched>/g, '');
        if (!url || url.includes('<')) continue;

        try {
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT_MS });
            count++;
        } catch (_) { /* expected for some admin routes */ }
    }
    process.stderr.write(`[+] Admin crawl: ${count} URLs visited\n`);
}

async function collectConsoleErrors(page, findings) {
    page.on('console', msg => {
        if (msg.type() === 'error') {
            findings.push({
                type: 'console_error',
                url: page.url(),
                message: msg.text().slice(0, 200),
            });
        }
    });
}

(async () => {
    process.stderr.write(`[*] Booyah Playwright crawler starting\n`);
    process.stderr.write(`[*] Routes: ${routes.length} total\n`);
    process.stderr.write(`[*] Target: ${BASE_URL}\n`);

    const frontendRoutes = routes.filter(r => r.area === 'frontend').slice(0, MAX_URLS);
    const adminRoutes = routes.filter(r => r.area === 'adminhtml').slice(0, 100);

    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        extraHTTPHeaders: { 'X-Booyah-Crawl': '1' },
    });

    // Frontend crawl
    const frontendPage = await context.newPage();
    collectConsoleErrors(frontendPage, findings);
    await crawlFrontend(frontendPage, frontendRoutes);
    await frontendPage.close();

    // Admin crawl
    if (adminRoutes.length > 0) {
        const adminPage = await context.newPage();
        collectConsoleErrors(adminPage, findings);
        const authed = await authenticateAdmin(adminPage);
        if (authed) {
            await crawlAdmin(adminPage, adminRoutes);
        }
        await adminPage.close();
    }

    await browser.close();

    // Write results
    const outDir = path.dirname(OUTPUT_FILE);
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    const reflections = findings.filter(f => ['probe_reflected', 'form_reflection'].includes(f.type));
    const summary = {
        total_findings: findings.length,
        reflections: reflections.length,
        probe_reflections: findings.filter(f => f.type === 'probe_reflected').length,
        form_reflections: findings.filter(f => f.type === 'form_reflection').length,
        console_errors: findings.filter(f => f.type === 'console_error').length,
    };

    fs.writeFileSync(OUTPUT_FILE, JSON.stringify({ summary, findings }, null, 2));
    process.stderr.write(`[+] Results: ${OUTPUT_FILE}\n`);
    process.stderr.write(`[+] Reflections found: ${reflections.length}\n`);
    console.log(JSON.stringify(summary));
})().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
