const { BrowserAutomation } = require('./browser-automation');
const { DOMManipulation } = require('./dom-manipulation');
const { UserFunctionalities } = require('./user-functionalities');
const { Parameters } = require('./parameters');
const { APIFuzzer } = require('./api-fuzzer');
const { TokenAnalyzer } = require('./token-analyzer');
const { EndpointCollector } = require('./endpoint-collector');
const { SessionHijacker } = require('./session-hijacker');
const { XSSHunter } = require('./xss-hunter');
const { CSRFTester } = require('./csrf-tester');
const { PrototypePollution } = require('./prototype-pollution');
const { PostMessageExplorer } = require('./postmessage-explorer');
const { StorageAuditor } = require('./storage-auditor');
const { EventInspector } = require('./event-inspector');
const { ClientSideScanner } = require('./client-side-scanner');

module.exports = {
  BrowserAutomation,
  DOMManipulation,
  UserFunctionalities,
  Parameters,
  APIFuzzer,
  TokenAnalyzer,
  EndpointCollector,
  SessionHijacker,
  XSSHunter,
  CSRFTester,
  PrototypePollution,
  PostMessageExplorer,
  StorageAuditor,
  EventInspector,
  ClientSideScanner,
  tools: [
    { name: 'browser-automation', class: BrowserAutomation, description: 'Playwright browser automation — navigate, fill, screenshot, intercept, HAR' },
    { name: 'dom-manipulation', class: DOMManipulation, description: 'DOM querying, mutation observation, element injection, storage inspection' },
    { name: 'user-functionalities', class: UserFunctionalities, description: 'Login, register, multi-account, session management, OAuth flows' },
    { name: 'parameters', class: Parameters, description: 'URL/body parameter extraction, mutation, pollution, fuzzing wordlists' },
    { name: 'api-fuzzer', class: APIFuzzer, description: 'HTTP method/header/param/rate-limit fuzzing, content-type probing' },
    { name: 'token-analyzer', class: TokenAnalyzer, description: 'JWT decode, alg=none, brute-force, JWK injection, kid traversal' },
    { name: 'endpoint-collector', class: EndpointCollector, description: 'JS bundle endpoint extraction, secret hunting, source maps' },
    { name: 'session-hijacker', class: SessionHijacker, description: 'Cookie audit, session fixation, entropy analysis, storage token detection' },
    { name: 'xss-hunter', class: XSSHunter, description: 'DOM/reflected/stored XSS, mXSS, CSP audit, polyglot generator' },
    { name: 'csrf-tester', class: CSRFTester, description: 'CSRF token strength, SameSite audit, CORS misconfig, PoC generator' },
    { name: 'prototype-pollution', class: PrototypePollution, description: 'Prototype pollution, DOM clobbering, library gadget detection' },
    { name: 'postmessage-explorer', class: PostMessageExplorer, description: 'postMessage listeners, origin validation, XSS chains, opener audit' },
    { name: 'storage-auditor', class: StorageAuditor, description: 'localStorage/IndexedDB/CacheAPI audit, sensitive data patterns, PII hunt' },
    { name: 'event-inspector', class: EventInspector, description: 'Event listener enum, clickjacking, UI redressing, keyboard/mouse capture' },
    { name: 'client-side-scanner', class: ClientSideScanner, description: 'Orchestrator — runs all 14 tools, consolidated report, P1 prioritization' }
  ],
  listTools() {
    return this.tools.map(t => ({ name: t.name, description: t.description }));
  },
  getTool(name) {
    return this.tools.find(t => t.name === name);
  }
};
