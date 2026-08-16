# Web Application Honeypot & Attack Detection System

A multi-endpoint honeypot built to simulate common attack surfaces, capture attacker behavior, and detect basic attack patterns in real time.

## What it does
- Simulates 5 realistic vulnerable endpoints (admin login, exposed config file, API enumeration, file upload, search)
- Logs every attempt with structured data (IP, timestamp, payload, headers)
- Detects brute-force login attempts (same IP, multiple attempts in a time window)
- Detects common SQL injection and XSS patterns in user input

## Tech stack
Node.js, Express, JavaScript

## Status
In active development — deployment and further analysis in progress.