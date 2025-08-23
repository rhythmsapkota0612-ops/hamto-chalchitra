const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');

const router = express.Router();

// Proxy iframe route
router.get('/proxy/iframe', async (req, res) => {
    try {
        const targetUrl = req.query.url;
        if (!targetUrl) {
            return res.status(400).send('Missing url query parameter');
        }

        const decodedUrl = decodeURIComponent(targetUrl);
        console.log('Proxying URL:', decodedUrl);

        const response = await axios.get(decodedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            },
            timeout: 10000,
        });

        // Preserve original content-type
        if (response.headers['content-type']) {
            res.set('Content-Type', response.headers['content-type']);
        }

        let html = response.data;
        const $ = cheerio.load(html);

        // Inject patch script for fetch/XHR
        $('head').prepend(`
            <script>
                (function() {
                    const originalFetch = window.fetch;
                    window.fetch = function(input, init) {
                        if (typeof input === 'string' && input.includes('https://livesport.su/api/')) {
                            input = input.replace('https://livesport.su/api/', '/proxy/api/');
                        }
                        return originalFetch(input, init);
                    };

                    const originalXHROpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url) {
                        if (url.includes('https://livesport.su/api/')) {
                            arguments[1] = url.replace('https://livesport.su/api/', '/proxy/api/');
                        }
                        return originalXHROpen.apply(this, arguments);
                    };
                })();
            </script>
        `);

        // Neutralize sandbox detection in inline scripts
        $('script').each((i, elem) => {
            let scriptContent = $(elem).html();
            if (scriptContent) {
                const sandboxPatterns = [
                    /window\.frameElement/gi,
                    /parent\s*[!=]=?\s*window/gi,
                    /top\s*[!=]=?\s*window/gi,
                    /window\s*[!=]=?\s*top/gi,
                    /self\s*[!=]=?\s*top/gi,
                    /frameElement/gi,
                    /\.sandbox/gi,
                    /getAttribute\s*\(\s*['"]sandbox['"]/gi,
                ];

                let hasSandboxDetection = sandboxPatterns.some(pattern => pattern.test(scriptContent));

                if (hasSandboxDetection) {
                    console.log('Found sandbox detection, neutralizing...');

                    scriptContent = scriptContent
                        .replace(/window\.frameElement/gi, 'null')
                        .replace(/frameElement/gi, 'null')
                        .replace(/parent\s*(!==?)\s*window/gi, 'false')
                        .replace(/parent\s*(===?)\s*window/gi, 'true')
                        .replace(/window\s*(!==?)\s*top/gi, 'false')
                        .replace(/window\s*(===?)\s*top/gi, 'true')
                        .replace(/self\s*(!==?)\s*top/gi, 'false')
                        .replace(/self\s*(===?)\s*top/gi, 'true')
                        .replace(/top\s*(!==?)\s*window/gi, 'false')
                        .replace(/top\s*(===?)\s*window/gi, 'true')
                        .replace(/\.getAttribute\s*\(\s*['"]sandbox['"]\s*\)/gi, 'null')
                        .replace(/\.hasAttribute\s*\(\s*['"]sandbox['"]\s*\)/gi, 'false')
                        .replace(/\.sandbox\s*=/gi, '.tmp_sandbox =')
                        .replace(/setAttribute\s*\(\s*['"]sandbox['"][^)]*\)/gi, '/* sandbox removed */')
                        .replace(/if\s*\(\s*window\s*!=\s*top\s*\)/gi, 'if(false)')
                        .replace(/if\s*\(\s*top\s*!=\s*window\s*\)/gi, 'if(false)')
                        .replace(/if\s*\(\s*parent\s*!=\s*window\s*\)/gi, 'if(false)')
                        .replace(/if\s*\(\s*window\s*!==\s*top\s*\)/gi, 'if(false)')
                        .replace(/if\s*\(\s*top\s*!==\s*window\s*\)/gi, 'if(false)')
                        .replace(/if\s*\(\s*parent\s*!==\s*window\s*\)/gi, 'if(false)');
                }

                $(elem).html(scriptContent);
            }
        });

        res.send($.html());

    } catch (error) {
        console.error('Proxy iframe error:', error.message);
        res.status(500).send(`Error fetching content: ${error.message}`);
    }
});



// API proxy route using middleware approach
router.use('/proxy/api', (req, res, next) => {
    // Set CORS headers for all API requests
    res.set({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Origin, X-Requested-With, Content-Type, Accept, Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '3600',
    });

    // Handle OPTIONS preflight request
    if (req.method === 'OPTIONS') {
        return res.status(200).send();
    }

    next();
});

router.use('/proxy/api', async (req, res) => {
    try {
        // Extract the API path
        const apiPath = req.originalUrl.replace('/proxy/api/', '');
        const targetUrl = `https://livesport.su/api/${apiPath}`;

        console.log(`Proxying API ${req.method} URL:`, targetUrl);

        let response;

        // Handle different HTTP methods
        if (req.method === 'GET') {
            response = await axios.get(targetUrl, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Referer': 'https://livesport.su',
                    'Accept': 'application/json, text/plain, */*',
                },
                timeout: 10000,
            });
        } else if (req.method === 'POST') {
            response = await axios.post(targetUrl, req.body, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Referer': 'https://livesport.su',
                    'Accept': 'application/json, text/plain, */*',
                    'Content-Type': req.headers['content-type'] || 'application/json',
                },
                timeout: 10000,
            });
        } else {
            return res.status(405).send('Method not allowed');
        }

        // Set content type from response
        if (response.headers['content-type']) {
            res.set('Content-Type', response.headers['content-type']);
        }

        res.send(response.data);

    } catch (error) {
        console.error('API Proxy error:', error.message);
        res.status(error.response?.status || 500).json({
            error: 'API request failed',
            message: error.message
        });
    }
});

// Handle OPTIONS for iframe endpoint
router.options('/proxy/iframe', (req, res) => {
    res.set({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
    });
    res.status(200).send();
});

module.exports = router;