#!/usr/bin/env node

// Simple wrapper to run the HTTP server (server-http.mjs)
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import and run the HTTP server module
const mainModule = path.join(__dirname, '..', 'server-http.mjs');
import(mainModule);
