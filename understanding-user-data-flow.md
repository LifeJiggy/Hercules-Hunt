# Understanding User Data Flow

A comprehensive methodology for mapping user data through the application to find trust-boundary violations, IDORs, privilege escalation paths, and mass assignment vulnerabilities. This is the single highest-leverage skill for finding critical bugs in modern web applications.

## Table of Contents

1. [The Core Question](#the-core-question)
2. [Why Data Flow Matters More Than Surface Scanning](#why-data-flow-matters-more-than-surface-scanning)
3. [Phase 1: Entry Points & Input Mapping](#phase-1-entry-points--input-mapping)
4. [Phase 2: Storage & Persistence Tracing](#phase-2-storage--persistence-tracing)
5. [Phase 3: Retrieval & Presentation](#phase-3-retrieval--presentation)
6. [Phase 4: Authorization Checkpoint Analysis](#phase-4-authorization-checkpoint-analysis)
7. [Data Flow Anti-Patterns](#data-flow-anti-patterns)
8. [Data Flow Diagramming](#data-flow-diagramming)
9. [Attack Patterns by Data Flow Violation](#attack-patterns-by-data-flow-violation)
10. [Language/Framework-Specific Anti-Patterns](#languageframework-specific-anti-patterns)
11. [Automation & Tooling](#automation--tooling)
12. [Real-World Examples](#real-world-examples)
13. [Checklist](#checklist)

---

## The Core Question

**Where does user A's data flow to a place where user B (or an unauthenticated user) can reach it?**

Every critical bug in a multi-tenant application comes down to a failure in data flow isolation. The data left user A's authorized boundary and landed somewhere user B could touch it. Your job is to find those boundaries and test whether they actually hold.

This is not about guessing IDs. It is about understanding the complete path data takes — from input through processing, storage, retrieval, and presentation — and finding every place where the tenant isolation breaks down.

---

## Why Data Flow Matters More Than Surface Scanning

Most bug bounty hunters spend their time on surface-level testing: "send a request, look at the response, try to change an ID." This finds low-hanging IDORs but misses the deep, high-impact bugs that come from understanding the full data flow.

| Approach | Finds | Misses |
|----------|-------|--------|
| Surface scanning (guess IDs) | Direct object reference bugs | Multi-step flows, GraphQL leaks, admin bypasses, caching violations |
| Data flow mapping | All of the above + chained attacks | Nothing — it includes all surface findings |

**The difference is methodology.** Surface scanning tests one endpoint. Data flow mapping tests the entire system.

---

## Phase 1: Entry Points & Input Mapping

### 1.1 Catalog Every Endpoint That Accepts User Data

Start with a complete inventory of endpoints that accept user-identifiable data. Group by function:

#### Profile & Account Management

```
POST   /api/user/profile          # Update user profile
PUT    /api/user/email            # Change email address
PUT    /api/user/password         # Change password
POST   /api/user/avatar           # Upload avatar image
GET    /api/user/settings         # Retrieve settings
PUT    /api/user/settings         # Update settings
POST   /api/user/address          # Add shipping address
DELETE /api/user/address/{id}     # Remove address
POST   /api/user/payment          # Add payment method
DELETE /api/user/payment/{id}     # Remove payment method
```

#### Document & File Management

```
POST   /api/documents/upload      # Upload document
GET    /api/documents/{id}        # Download/view document
GET    /api/documents             # List documents
DELETE /api/documents/{id}        # Delete document
PUT    /api/documents/{id}        # Update document metadata
POST   /api/documents/{id}/share  # Share document with another user
GET    /api/documents/{id}/share  # List users who can access document
```

#### Communication & Messaging

```
POST   /api/messages/send         # Send message
GET    /api/messages/{id}         # View message
GET    /api/messages              # List messages
POST   /api/comments              # Add comment
GET    /api/comments/{id}         # View comment
GET    /api/comments              # List comments (on what scope?)
POST   /api/threads               # Create conversation thread
GET    /api/threads/{id}          # View thread
PUT    /api/threads/{id}/users    # Add/remove users from thread
```

#### Commerce & Transactions

```
POST   /api/orders                # Create order
GET    /api/orders/{id}           # View order details
GET    /api/orders                # List orders
POST   /api/invoices              # Generate invoice
GET    /api/invoices/{id}         # View invoice
POST   /api/payments              # Process payment
GET    /api/payments/{id}         # View payment details
POST   /api/subscriptions         # Create subscription
GET    /api/subscriptions/{id}    # View subscription
POST   /api/refunds               # Request refund
```

#### Admin & Privileged Operations

```
GET    /api/admin/users           # List all users
GET    /api/admin/users/{id}      # View specific user details
PUT    /api/admin/users/{id}      # Modify user account
POST   /api/admin/impersonate     # Login as another user
GET    /api/admin/logs            # View system logs
POST   /api/admin/config          # Update system configuration
GET    /api/admin/reports         # View admin reports
DELETE /api/admin/cleanup         # Administrative cleanup
```

### 1.2 Map Every Field That Carries a User Identifier

For each endpoint, document the fields that carry user identity:

#### Direct Identifiers
```
user_id         → User's unique ID (integer, UUID, hash)
account_id      → Account/tenant identifier
organization_id → Organization/workspace identifier
email           → Email address (often an identifier)
username        → Username (often unique)
phone           → Phone number
```

#### Object Identifiers That Imply Ownership
```
order_id        → Belongs to a user
document_id     → Belongs to a user or organization
invoice_id      → Belongs to a user
payment_id      → Belongs to a user
session_id      → Tied to a specific user session
api_key_id      → Belongs to a user account
webhook_id      → Belongs to a user account
integration_id  → Belongs to a user account
```

#### Indirect/Predictable Identifiers
```
callback_url    → May contain user-specific tokens
redirect_url    → May leak user context
webhook_url     → Often contains user/account IDs
embed_url       → May contain identifiers
export_filename → Often contains user/account IDs
```

### 1.3 Identify Data Input Channels Beyond REST

Data doesn't only enter through REST APIs. Map every channel:

#### GraphQL
```
POST /graphql
query:
  mutation CreateDocument($input: DocumentInput!) {
    createDocument(input: $input) { id title owner { id } }
  }
```

**Key difference:** GraphQL resolvers often bypass REST-style authorization because they operate at the data layer. A resolver that fetches `documents` without a user context filter returns all documents.

#### WebSocket
```
WS /ws/notifications
WS /ws/live-updates
WS /ws/collaboration
WS /ws/chat
```

**Key difference:** WebSocket connections are often authenticated once at connection time, then all subsequent messages are assumed authorized. If the server doesn't re-validate per-message, any connected client can listen to any channel.

#### Server-Sent Events (SSE)
```
GET /api/events
GET /api/stream
```

**Key difference:** SSE endpoints sometimes omit authorization headers entirely because they use EventSource API which has limited header support. If auth is in query params, it can be shared or leaked.

#### File Uploads (async processing)
```
POST /api/files/upload
→ Server returns { file_id: "abc123", status: "processing" }
→ Later: GET /api/files/abc123/status
```

**Key difference:** Async processing often means the file goes through a queue, and the queue worker may not have user context. If the worker stores the file with just the file_id, any user who knows the ID can access it.

#### Webhook Callbacks
```
POST /api/webhooks/register
→ Server stores webhook URL
→ Later: POST <webhook_url> with sensitive data
```

**Key difference:** Webhook delivery endpoints may include user data in the payload, and the target URL belongs to the user. But if other users can read webhook logs or modify webhook URLs, data flows to the wrong recipient.

#### OAuth/SSO Callbacks
```
GET /auth/callback?code=abc&state=xyz
→ Server exchanges code for token
→ Token contains user identity data
```

**Key difference:** OAuth callbacks carry authentication data through URLs. If the server logs these URLs, the authorization code leaks into log files. If logs are shared, auth codes leak.

#### Import/Export
```
POST /api/import/csv
GET /api/export/csv
GET /api/export/{format}
```

**Key difference:** Exported data often includes more fields than the API returns in JSON. CSV exports may include hidden fields (internal IDs, timestamps, internal notes). Imports may process data that isn't visible elsewhere.

---

## Phase 2: Storage & Persistence Tracing

### 2.1 Database Layer

Every piece of user data ends up in a database. Understand the schema:

#### Multi-Tenant Patterns

**Shared table with tenant column (correct):**
```sql
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

SELECT * FROM documents WHERE id = $1 AND owner_id = $2;
```

**Shared table without tenant column (vulnerable):**
```sql
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    -- Missing: owner_id
    created_at TIMESTAMP DEFAULT NOW()
);

SELECT * FROM documents WHERE id = $1;
```

**Separate database per tenant (secure but expensive):**
```sql
-- Database: tenant_123
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Rows with ownership implied by foreign key (fragile):**
```sql
SELECT d.* FROM documents d
JOIN orders o ON d.order_id = o.id
WHERE d.id = $1;  -- Missing: AND o.user_id = $current_user
```

**Questions to ask for every table:**

1. Is there a `user_id`, `owner_id`, `account_id`, or `tenant_id` column?
2. Is it `NOT NULL` and `FOREIGN KEY` constrained?
3. Does every query that accesses this table include a WHERE clause on this column?
4. Are there any queries that join across tenant boundaries (e.g., reporting, analytics, admin)?
5. Are there any stored procedures, triggers, or views that bypass the tenant filter?

#### Caching Layer

Caches are where data flows most commonly break because cache keys often omit user context.

**Cache key patterns:**

```
user:123:profile           → User-scoped (correct)
profile:123                → Not user-scoped (leaks to whoever requests profile:123)
document:abc               → Not scoped to user (anyone who knows ID can access)
user:123:document:abc      → User-scoped (correct)
```

**Test for cache-based data leaks:**

1. User A creates a resource → GET response is cached
2. User B requests the same resource URL → if they get User A's data, cache is shared across users

**Cache types to check:**

| Cache Type | Scope | Leak Risk |
|------------|-------|-----------|
| CDN cache (Cloudflare, Fastly) | URL-based, shared | High if URLs don't contain user context |
| Application cache (Redis, Memcached) | Key-based | High if keys don't include user ID |
| HTTP cache (Varnish, Nginx) | URL + headers | Medium — varies by configuration |
| Browser cache | Per-browser | Low — only affects same browser |
| Service worker cache | Per-origin | Medium — can be exploited via SW |

#### Queue / Message Broker

Async processing queues often strip user context:

```python
# Vulnerable pattern
def create_document(user, content):
    doc_id = db.insert(content, owner_id=user.id)
    queue.send({"doc_id": doc_id, "content": content})
    # Missing: {"doc_id": doc_id, "content": content, "owner_id": user.id}

# Worker processes:
def process_document(message):
    doc = process(message['content'])
    db.update(message['doc_id'], processed=doc)
    # Which user does this belong to? The worker doesn't know.
```

**Queues to check:** RabbitMQ, Redis pub/sub, AWS SQS/SNS, Azure Service Bus, Google Pub/Sub, Kafka.

#### Object Storage (S3/GCS/Azure Blob)

Object storage keys that don't include user context:

```shell
# Vulnerable key pattern
GET /files/documents/{document_id}.pdf
# → Any user who knows document_id can access

# Secure key pattern
GET /files/users/{user_id}/documents/{document_id}.pdf
# → Even with document_id, need user_id
```

**Signed URLs:**

```shell
# Generated URL valid for 1 hour:
https://storage.example.com/files/abc123.pdf?Signature=xyz&Expires=1234567890
```

If the signed URL generation doesn't scope to the requesting user, user A can share their signed URLs with user B.

**Pre-signed upload URLs:**

```python
# Vulnerable: presigned URL allows upload to shared prefix
url = s3.generate_presigned_url(
    Bucket='uploads',
    Key=f'{uuid4()}.pdf',  # Random but shared namespace
    ...
)

# Secure: presigned URL scoped to user
url = s3.generate_presigned_url(
    Bucket='uploads',
    Key=f'user_{user.id}/{uuid4()}.pdf',  # Scoped to user
    ...
)
```

#### Full-Text Search Indexes

Search engines often index across all users:

```json
// Elasticsearch query
POST /documents/_search
{
  "query": {
    "match": { "content": "confidential" }
  }
}
```

If the query doesn't have a `term` filter on `owner_id`, the search returns documents from all users.

**Questions to ask:**

1. Is the search index partitioned by tenant?
2. Does every search query include a tenant filter?
3. Are search results cached and shared across users?

#### Logging & Monitoring

Centralized logging systems (ELK, Datadog, Splunk) often receive user data:

```
2026-06-16 10:00:00 [INFO] User 123 requested document 456
2026-06-16 10:00:01 [DEBUG] Request body: {"user_id": 123, "document_content": "confidential"}
```

If logs are accessible via a web interface and the interface doesn't filter by user, user A can search for user B's data in logs.

**Check for:**

- Log viewer endpoints (`/api/logs`, `/api/activity`, `/api/audit`)
- Error reporting dashboards that show user data
- Admin audit logs that are accessible to non-admin users
- Search functionality in logs

---

## Phase 3: Retrieval & Presentation

### 3.1 Direct Object Access

The most straightforward data flow violation:

```
User A → DELETE /api/documents/123
User B → GET /api/documents/123    → User A's document
```

**Test every HTTP method on every object endpoint:**

| Method | What to test |
|--------|-------------|
| GET | Read another user's object |
| PUT/PATCH | Modify another user's object |
| DELETE | Delete another user's object |
| POST | Create object under another user's account |

### 3.2 List Endpoints

List endpoints are the most common source of mass data leaks:

```json
// /api/documents — returns this user's documents
{
  "documents": [
    { "id": 123, "title": "My Document", "owner_id": 456 }
  ]
}
```

**Test parameters that might remove the tenant filter:**

| Parameter | Example | What to test |
|-----------|---------|-------------|
| Pagination | `?page=1&limit=50` | Does pagination bypass the user filter? |
| Sorting | `?sort=created_at` | Does sorting reveal other users' data? |
| Filtering | `?status=active` | Does filtering remove the user scope? |
| Search | `?q=keyword` | Does search go across all users? |
| Export | `?format=csv` | Does export include all users' data? |
| Admin flag | `?admin=true` | Does an undocumented admin flag exist? |
| Debug | `?debug=1` | Does debug mode show all data? |
| Internal | `?internal=true` | Does internal flag bypass auth? |

### 3.3 Search Endpoints

Search endpoints are particularly dangerous because they're designed to return relevant results — and the definition of "relevant" may not include user scoping:

```
GET /api/search?q=invoices&user_id=all
GET /api/search?q=invoices&scope=global
GET /api/search?q=invoices&include_all=true
GET /api/search?q=invoices&tenant_id=*
```

**Test search scope parameters:**

- `scope=global`, `scope=all`, `scope=admin`
- `user_id=all`, `user_id=*`, `user_id=0`, `user_id=-1`
- `include_all=true`, `include_all=1`
- `tenant_id=*`, `organization_id=all`
- `admin=true`, `is_admin=1`

### 3.4 Export & Download

Export endpoints are designed to dump all data:

```
GET /api/export/users.csv
GET /api/export/transactions.json
GET /api/export/reports.zip
GET /api/documents/batch-export
POST /api/export/custom
```

**Test export scope:**

- Does the export include only the current user's data?
- Can you specify another user's ID in the export request?
- Can you export admin-level data with a user-level token?

### 3.5 Admin Interfaces

Admin panels often lack proper authorization on individual operations:

```
GET /api/admin/users              → Should require admin role
GET /api/admin/users/123          → Does it check admin role?
PUT /api/admin/users/123/suspend  → Is there a role check?
```

**Test admin endpoints for Horizontal Privilege Escalation:**

Even if an admin endpoint requires admin role, it may allow admin A to access admin B's data:

```
GET /api/admin/users?admin_id=2   → Admin A tries to access Admin B's interface
GET /api/admin/logs?scope=global  → Admin A reads all admin activity
```

### 3.6 GraphQL Resolvers

GraphQL adds a unique attack surface because:

1. **Over-fetching**: The client requests exactly what it needs, and the resolver fetches it. If the resolver doesn't filter by user context, all data is returned.

2. **N+1 joins**: If a resolver chain fetches related objects without user context, data from multiple tenants is returned.

3. **Introspection bypass**: Resolver names often reveal internal structures (e.g., `allDocuments`, `adminPanel`).

**GraphQL-specific patterns:**

```graphql
# Query without arguments
query {
  documents {           # Resolver may return ALL documents
    id title content
    owner { email name }
  }
}

# Query with IDOR
query {
  document(id: 123) {  # Does it check ownership?
    id title content
    owner { email }
  }
}

# Mutation without ownership check
mutation {
  updateDocument(id: 123, input: {title: "Hacked"}) {
    id title
  }
}

# Batch query for enumeration
query {
  user1: document(id: 1) { title content }
  user2: document(id: 2) { title content }
  user3: document(id: 3) { title content }
}
```

### 3.7 Real-Time Channels (WebSocket, SSE)

Real-time channels are often overlooked in data flow testing:

#### Connection-Level Auth

```
// Client connects:
const ws = new WebSocket('wss://api.target.com/ws', ['token_xyz']);
```

If the server authenticates at connection time and doesn't re-validate per-message:

```json
// User A sends:
{ "type": "subscribe", "channel": "user_456_updates" }
// User B's updates flow to User A
```

#### Channel Naming

Channel names that include user IDs can be guessed:

```
ws://api.target.com/ws/user/123
ws://api.target.com/ws/order/456
ws://api.target.com/ws/document/abc
```

If the server doesn't validate that the requesting user owns the channel, any user can subscribe to any channel.

#### Broadcast Misconfiguration

```json
// Server broadcasts to ALL connected clients:
{ "type": "notification", "user_id": 123, "message": "Your password was changed" }
```

If the server doesn't filter by recipient, every connected client sees every notification.

---

## Phase 4: Authorization Checkpoint Analysis

### 4.1 Mapping Checkpoints

Every data flow has checkpoints where authorization should be enforced:

```
Request → Gateway (1) → API Gateway (2) → Service (3) → Database (4) → Response
```

| Checkpoint | Location | Enforcement |
|-----------|----------|-------------|
| 1 | Edge/Load Balancer | IP allowlist, rate limiting (not auth) |
| 2 | API Gateway | JWT validation, token expiry, scope check |
| 3 | Service Layer | Business logic, tenant isolation |
| 4 | Database | Row-level security, tenant views |

**The Gap:** Most applications check at checkpoint 2 (token is valid) but skip checkpoint 3 (tenant isolation).

### 4.2 Where Authorization Actually Fails

**Layer 3 failures (most common):**

```python
# Service layer — vulnerable
def get_document(document_id):
    doc = db.query("SELECT * FROM documents WHERE id = ?", document_id)
    return doc
    # Missing: AND owner_id = current_user.id
```

**Layer 2 failures (less common but critical):**

```python
# API Gateway — vulnerable
def authorize(token, resource):
    user = verify_jwt(token)
    if user.is_expired():
        return 401
    return user  # Missing: check user.scope for the resource
```

**Layer 4 failures (rare but catastrophic):**

```sql
-- Database layer — vulnerable
CREATE VIEW all_documents AS
SELECT * FROM documents;
-- Missing: WHERE owner_id = current_setting('app.current_user_id')::int
```

### 4.3 Testing Each Checkpoint

**Checkpoint 2 (API Gateway):**

- Remove the auth header — what happens?
- Send an expired token — is there a fallback?
- Send a token for user A to an endpoint for user B — does the gateway catch it?
- Send a token with missing scopes — does the gateway validate scopes?

**Checkpoint 3 (Service Layer):**

- Change the object ID in a request for user A to an object owned by user B
- Can user A list objects that belong to user B?
- Can user A modify objects that belong to user B through a different endpoint?
- Can user A act on objects through batch operations?

**Checkpoint 4 (Database):**

- Are there stored procedures that bypass the ORM?
- Are there database views that include all tenants?
- Can user A query user B's data through a different database connection?

---

## Data Flow Anti-Patterns

### Anti-Pattern 1: Implicit Trust in Sequential IDs

```json
// Request: POST /api/order/create
{ "product_id": 123, "quantity": 1 }

// Response:
{ "order_id": 456, "status": "created" }

// GET /api/order/456 — Fails to check ownership
```

**Pattern:** The application creates a resource and returns its ID, assuming the user will only access their own resources. No ownership check on subsequent reads.

**Test:** Create a resource, note the ID, log in as another user, access the resource by ID.

### Anti-Pattern 2: The Admin Bypass in List Endpoints

```
GET /api/users                  → 403 Forbidden (expected)
GET /api/users?role=admin       → 200 OK (bypass via param)
GET /api/users/                 → 200 OK (trailing slash)
GET /api/users?limit=1          → 200 OK (pagination param)
GET /api/users?page=1           → 200 OK (page param)
GET /api/users?admin=true       → 200 OK (admin flag)
GET /api/users?internal=1       → 200 OK (internal flag)
GET /api/users?X-Forwarded-For=127.0.0.1  → 200 OK (internal network)
```

**Pattern:** List endpoints check for admin role but remove the check when certain parameters are present. This is usually a configuration-based bypass where the framework applies different middleware based on parameter presence.

**Test:** Fuzz every list endpoint with common parameter overrides.

### Anti-Pattern 3: UUIDs as a Security Mechanism

```json
// Developer response: "But we use UUIDs, nobody can guess them"
{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "owner_id": "user_abc",
  "private_note": "This is sensitive"
}
```

**Pattern:** Development teams assume that UUIDs provide authorization because they're unguessable. They do not. Authorization is about *who can access a resource*, not *who can find the resource*.

**UUID Leak Vectors:**
- Referer header when navigating between pages
- WebSocket messages that include UUIDs of other users' resources
- Error messages that include UUIDs of system resources
- API responses that include UUIDs in nested objects
- Collaborative features that share UUIDs between users
- Browser history for SPA routes
- Server logs accessible via admin interfaces
- Export files that include UUIDs

**Test:** Treat UUID resources the same as integer ID resources — attempt to access another user's UUID via the same endpoint.

### Anti-Pattern 4: GraphQL N+1 Data Leakage

```graphql
query {
  users {
    documents {
      title
      content
    }
  }
}
```

**Pattern:** The user resolver returns all users. The document resolver under each user fetches documents. If the document resolver doesn't scope to the parent user, it returns documents for the current user (all of them).

**Why this happens:**
```javascript
// Resolver for User.documents
documents(parent, args, context) {
  // parent is the user object from the parent resolver
  // If parent is every user, this returns every user's documents
  return db.query("SELECT * FROM documents WHERE owner_id = ?", parent.id);
}
```

**Test:**
- Query nested resources without parent filters
- Compare results with and without parent context

### Anti-Pattern 5: WebSocket Auth-on-Connect

```
WS /ws/chat (authenticated with token during handshake)

User A sends: { "channel": "user_456", "message": "hello" }
Server delivers to user_456 without checking that User A is allowed to message User 456
```

**Pattern:** WebSocket authentication at connection time creates a session, but individual messages within that session are not re-authorized. If the user can send messages on any channel, they can impersonate other users or access restricted channels.

**Testing WebSocket auth:**
1. Connect as User A
2. Try to subscribe to User B's private channel
3. Try to send messages to User B's channel
4. Try to access admin channels
5. Try to send system-level commands

### Anti-Pattern 6: Server-Side Render Data Leakage

Hidden in HTML comments, script tags, and form fields:

```html
<!-- User data: {"id": 123, "email": "admin@target.com", "role": "superadmin"} -->

<input type="hidden" name="user_id" value="123">

<script>
  window.__INITIAL_STATE__ = {
    currentUser: { id: 123, email: "admin@target.com", role: "admin" },
    allUsers: [ /* Data for ALL users rendered on this page */ ]
  };
</script>

<div data-user-id="123" data-role="admin">...</div>
```

**Pattern:** Server-side templates and frameworks embed user data in the HTML for the client-side JavaScript. If the template includes data for all users (e.g., in an admin list), that data is visible in the page source even if the UI hides it.

**Test:** View page source on every authenticated page. Search for:
- `__INITIAL_STATE__`, `__NEXT_DATA__`, `__NUXT__`, `window.__`
- `data-*` attributes with user data
- HTML comments between component renders
- Hidden input fields
- JSON in script tags

### Anti-Pattern 7: Mass Assignment in Data Flow

```
POST /api/user/profile
Content-Type: application/json

{ "name": "New Name", "email": "new@email.com" }

// The same endpoint also accepts:
{ "name": "New Name", "email": "new@email.com", "role": "admin", "credits": 999999 }
```

**Pattern:** The same endpoint that accepts user data for legitimate fields also accepts sensitive fields. If the server doesn't validate which fields can be updated, you can escalate privileges or modify other users' data.

**Mass Assignment Vectors:**
- `is_admin`, `role`, `permissions`, `scope`
- `credits`, `balance`, `points`, `tokens`
- `verified`, `confirmed`, `active`, `status`
- `user_id`, `owner_id`, `account_id`
- `referrer_id`, `invited_by`
- `internal_note`, `note`, `comment`

**Test:** Send every endpoint every field you can think of that modifies security properties.

### Anti-Pattern 8: CORS Misconfiguration Enabling Data Exfiltration

```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Pattern:** When combined with a data flow vulnerability, CORS misconfigurations allow attacker-controlled pages to exfiltrate user data.

**Dangerous CORS configurations:**
- `Access-Control-Allow-Origin: *` (with Allow-Credentials) — never valid
- `Access-Control-Allow-Origin: null` — can be triggered by sandboxed iframes
- `Access-Control-Allow-Origin: https://attacker.com` — if origin reflection exists
- Dynamic origin that reflects request origin without validation

**Test:**
1. Find a data flow vulnerability (e.g., an endpoint that returns another user's data)
2. Check if CORS allows the response to be read by JavaScript from another origin
3. If combined, create a PoC page that exfiltrates the data

### Anti-Pattern 9: Object Reference in URLs

```
https://app.target.com/user/123/settings
https://app.target.com/invoice/INV-2024-0001/download
https://app.target.com/report/shared/abc123
```

When user identifiers appear in URLs, they can be:
- Changed to access other users' resources
- Leaked through Referer headers
- Logged in analytics and server logs
- Cached by CDN or browser

### Anti-Pattern 10: Referer Header Data Leakage

When an application links to an external resource, the current page URL (which may contain user-scoped identifiers) is sent in the Referer header:

```
User A visits: https://app.target.com/invoices/INV-001
User A clicks a link to: https://external-site.com/help
External site receives Referer: https://app.target.com/invoices/INV-001
```

If the external site is attacker-controlled or compromised, user identifiers are leaked.

**Mitigation:** Use `rel="noreferrer"` on external links, but this is often missing.

### Anti-Pattern 11: Webhook URL Manipulation

```
POST /api/webhooks
{ "url": "https://user-controlled.com/hook", "events": ["order.created"] }
```

**Pattern:** Webhooks send user data to external URLs. If user A can read or modify user B's webhook URLs, user A can receive user B's data.

**Check:**
1. Can you list all webhooks (including other users')?
2. Can you modify another user's webhook URL?
3. Can you create a webhook for events you shouldn't have access to?

---

## Data Flow Diagramming

For critical features, draw the complete data flow diagram:

```
                        ╔═══════════════════╗
                        ║    [User A]       ║
                        ╚══════╤════════════╝
                               │ POST /api/report
                               ▼
                    ╔══════════════════════════╗
                    ║    API Gateway           ║
                    ║  ├─ Auth check: token OK ║
                    ║  └─ Rate limit: OK       ║
                    ╚══════════╤═══════════════╝
                               │ Forward request
                               ▼
                    ╔══════════════════════════╗
                    ║    Reports Service       ║
                    ║  ├─ Validate input       ║
                    ║  ├─ Create report row    ║
                    ║  │  owner_id = A.id      ║
                    ║  ├─ Enqueue processing   ║
                    ║  └─ Return report        ║
                    ╚══════════╤═══════════════╝
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
           ╔══════════════════╗  ╔══════════════════╗
           ║    Database      ║  ║    Queue          ║
           ║  reports table   ║  ║  report.processed ║
           ║  id  │ owner_id  ║  ╚════════╤═════════╝
           ║  1   │  A        ║           │
           ║  2   │  B        ║           ▼
           ╚══════════════════╝  ╔══════════════════╗
                                 ║    Worker         ║
                                 ║  Process report   ║
                                 ║  → Update DB      ║
                                 ╚══════════════════╝

                        ╔═══════════════════╗
                        ║    [User B]       ║
                        ╚══════╤════════════╝
                               │ GET /api/reports
                               ▼
                    ╔══════════════════════════╗
                    ║    API Gateway           ║
                    ╚══════════╤═══════════════╝
                               │ Forward request
                               ▼
                    ╔══════════════════════════╗
                    ║    Reports Service       ║
                    ║  SELECT * FROM reports   ║
                    ║  WHERE owner_id = B.id   ║  ← THIS IS THE CHECKPOINT
                    ╚══════════════════════════╝
```

**Questions this diagram answers:**

1. Does the `WHERE` clause include `owner_id = $current_user`? — If not, user B sees user A's reports.
2. Is the filter applied in the service layer, database layer, or not at all?
3. Is the queue message scoped to the user? — If not, workers may process other users' data.
4. What happens if the database query fails? — Does the error message reveal data?
5. What happens if the cache is hit? — Does the cache key include user context?

---

## Attack Patterns by Data Flow Violation

### Pattern 1: Horizontal IDOR

User A accesses User B's data of the same privilege level.

```
GET /api/documents/789  → User A with token for A → Returns User B's document
```

**Data flow failure:** The service layer query is missing `AND owner_id = current_user.id`.

### Pattern 2: Vertical IDOR (Privilege Escalation)

User A accesses admin-level data.

```
GET /api/admin/users    → User A → Returns all users (admin-only endpoint)
```

**Data flow failure:** The API gateway skips the admin role check, or the endpoint has a parameter that bypasses it.

### Pattern 3: Mass Assignment

User A sets a privileged field on their own or another user's resource.

```
PUT /api/user/profile   → { "role": "admin" } → User A is now admin
```

**Data flow failure:** The service layer accepts and processes fields that should be read-only or scope-limited.

### Pattern 4: Data Leakage via Error Messages

User A triggers an error that reveals User B's data.

```
GET /api/documents/999  → Document not found: "Document 999 doesn't exist."
GET /api/documents/789  → (User B's document) "You don't have access to User B's document."
```

**Data flow failure:** Error messages reveal existence of resources across tenant boundaries.

### Pattern 5: Data Leakage via Timing Side Channels

User A can determine if a resource exists by measuring response time.

```
GET /api/documents/789  → (exists, owned by B) → 200 OK in 50ms
GET /api/documents/999  → (doesn't exist)      → 404 in 50ms
```

Same timing = no timing side channel.
Different timing = timing side channel reveals existence.

### Pattern 6: Cache-Based Data Leakage

User B receives cached response from User A's request.

```
User A requests: GET /api/reports
CDN caches response for: /api/reports
User B requests: GET /api/reports
CDN returns cached response → User B sees User A's reports
```

**Data flow failure:** Cache key doesn't include user context.

### Pattern 7: Cross-Tenant Data Flow via Shared Infrastructure

User A's data leaks into User B's processing pipeline.

```
User A uploads file → Queue worker processes file → File stored in shared bucket
User B reads file → File exists in shared bucket → User B sees User A's file
```

**Data flow failure:** Shared infrastructure (queues, buckets, databases) without tenant isolation.

---

## Language/Framework-Specific Anti-Patterns

### Node.js / Express

```javascript
// Vulnerable
app.get('/api/documents/:id', (req, res) => {
    const doc = db.get('SELECT * FROM documents WHERE id = ?', req.params.id);
    res.json(doc);
    // Missing: AND owner_id = ?
});

// ORM vulnerable
app.get('/api/documents/:id', async (req, res) => {
    const doc = await Document.findByPk(req.params.id);
    res.json(doc);
    // Missing: where: { owner_id: req.user.id }
});
```

### Python / Django

```python
# Vulnerable
@api_view(['GET'])
def get_document(request, document_id):
    doc = Document.objects.get(id=document_id)
    return Response(doc.data)
    # Missing: filter(owner=request.user)

# Django REST Framework vulnerable ViewSet
class DocumentViewSet(viewsets.ModelViewSet):
    queryset = Document.objects.all()  # Returns ALL documents
    serializer_class = DocumentSerializer
    # Missing: def get_queryset(self): return Document.objects.filter(owner=self.request.user)
```

### Python / Flask

```python
# Vulnerable
@app.route('/api/documents/<int:document_id>')
@login_required
def get_document(document_id):
    doc = db.execute('SELECT * FROM documents WHERE id = ?', (document_id,)).fetchone()
    return jsonify(doc)
    # Missing: AND owner_id = ?
```

### Ruby on Rails

```ruby
# Vulnerable
def show
  @document = Document.find(params[:id])
  render json: @document
  # Missing: @document = current_user.documents.find(params[:id])
end
```

### Java / Spring

```java
// Vulnerable
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
    // Missing: .findByIdAndOwnerId(id, currentUser.getId())
}
```

### Go / Gin

```go
// Vulnerable
func GetDocument(c *gin.Context) {
    id := c.Param("id")
    var doc Document
    db.First(&doc, id)
    c.JSON(200, doc)
    // Missing: db.Where("owner_id = ?", userID).First(&doc, id)
}
```

### .NET / C#

```csharp
// Vulnerable
[HttpGet("{id}")]
public async Task<ActionResult<Document>> GetDocument(int id)
{
    var document = await _context.Documents.FindAsync(id);
    return document;
    // Missing: var document = await _context.Documents
    //     .FirstOrDefaultAsync(d => d.Id == id && d.OwnerId == userId);
}
```

---

## Automation & Tooling

### 1. Automated Endpoint Discovery

```python
import requests
import json
from urllib.parse import urljoin

class DataFlowScanner:
    def __init__(self, base_url, token_a, token_b):
        self.base_url = base_url
        self.headers_a = {"Authorization": f"Bearer {token_a}"}
        self.headers_b = {"Authorization": f"Bearer {token_b}"}
        
    def discover_endpoints(self, paths):
        """Test a list of potential API paths for data flow issues."""
        results = []
        for path in paths:
            # Test as user A
            resp_a = requests.get(
                urljoin(self.base_url, path),
                headers=self.headers_a
            )
            
            if resp_a.status_code != 200:
                continue
                
            # Extract IDs from user A's response
            ids_a = self._extract_ids(resp_a.json())
            
            # Test each ID as user B
            for obj_id in ids_a[:10]:
                id_path = f"{path}/{obj_id}"
                resp_b = requests.get(
                    urljoin(self.base_url, id_path),
                    headers=self.headers_b
                )
                
                if resp_b.status_code == 200 and resp_b.text != resp_a.text:
                    results.append({
                        "endpoint": id_path,
                        "user_a_id": obj_id,
                        "user_a_data": resp_a.json(),
                        "user_b_data": resp_b.json(),
                        "leak": True
                    })
                    
        return results
    
    def _extract_ids(self, data):
        """Recursively extract numeric and UUID IDs from JSON."""
        ids = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key.endswith('_id') or key == 'id':
                    ids.append(value)
                ids.extend(self._extract_ids(value))
        elif isinstance(data, list):
            for item in data:
                ids.extend(self._extract_ids(item))
        return ids
```

### 2. Batch IDOR Testing

```python
def test_batch_idor(base_url, tokens, endpoints):
    """Test IDOR across multiple users and endpoints."""
    results = []
    users = list(tokens.items())  # [(user_name, token), ...]
    
    for endpoint in endpoints:
        # Each user accesses every other user's resources
        for i, (user_a, token_a) in enumerate(users):
            for j, (user_b, token_b) in enumerate(users):
                if i == j:
                    continue
                    
                # User A creates a resource
                create_resp = requests.post(
                    urljoin(base_url, endpoint),
                    headers={"Authorization": f"Bearer {token_a}"},
                    json={"title": f"test_{user_a}_{user_b}"}
                )
                
                if create_resp.status_code != 200:
                    continue
                    
                resource_id = self._get_resource_id(create_resp.json())
                
                # User B tries to access it
                access_resp = requests.get(
                    urljoin(base_url, f"{endpoint}/{resource_id}"),
                    headers={"Authorization": f"Bearer {token_b}"}
                )
                
                if access_resp.status_code == 200:
                    results.append({
                        "resource_owner": user_a,
                        "accessing_user": user_b,
                        "endpoint": f"{endpoint}/{resource_id}",
                        "data": access_resp.json()
                    })
                    
    return results
```

### 3. Cache Poisoning / Cache-Based Data Leak Scanner

```python
def scan_cache_leaks(base_url, endpoints, token_a, token_b):
    """Check if CDN/application cache serves user-specific data across users."""
    results = []
    
    for endpoint in endpoints:
        # Check if responses are cached
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}
        
        resp_1a = requests.get(urljoin(base_url, endpoint), headers=headers_a)
        resp_2a = requests.get(urljoin(base_url, endpoint), headers=headers_a)
        resp_1b = requests.get(urljoin(base_url, endpoint), headers=headers_b)
        
        # Compare responses
        if resp_1b.text == resp_1a.text and resp_1b.status_code == 200:
            # User B got User A's data — cache leak
            results.append({
                "endpoint": endpoint,
                "type": "cache_leak",
                "user_a_data": resp_1a.text[:200],
                "user_b_data": resp_1b.text[:200]
            })
            
        # Check Age header for cached responses
        if 'Age' in resp_2a.headers:
            results.append({
                "endpoint": endpoint,
                "type": "cdn_cached",
                "age": resp_2a.headers['Age'],
                "cf_cache_status": resp_2a.headers.get('CF-Cache-Status', 'N/A')
            })
            
    return results
```

### 4. GraphQL Data Flow Testing

```python
def scan_graphql_data_flow(endpoint, token_a, token_b):
    """Test GraphQL resolvers for data flow issues."""
    queries = [
        # Batch queries
        """
        query {
            user1: document(id: 1) { id title content owner { email } }
            user2: document(id: 2) { id title content owner { email } }
            user3: document(id: 3) { id title content owner { email } }
        }
        """,
        
        # Unauthenticated access
        """
        query {
            documents { id title content owner { email } }
        }
        """,
        
        # Unscoped access
        """
        query {
            __typename
            allDocuments { id title }
            documents { id title }
        }
        """,
        
        # Parameter injection
        """
        query($id: Int!) {
            document(id: $id) { id title content }
        }
        """,
        
        # Mutation testing
        """
        mutation($id: Int!, $input: DocumentInput!) {
            updateDocument(id: $id, input: $input) { id title }
        }
        """
    ]
    
    results = []
    for query in queries:
        resp_a = requests.post(endpoint, 
            json={"query": query},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        resp_b = requests.post(endpoint, 
            json={"query": query},
            headers={"Authorization": f"Bearer {token_b}"}
        )
        
        if resp_a.text != resp_b.text:
            results.append({
                "query": query,
                "user_a_response": resp_a.json(),
                "user_b_response": resp_b.json(),
                "differs": True
            })
            
    return results
```

---

## Real-World Examples

### Example 1: The Shared Invoice IDOR

**Target:** A SaaS invoicing platform
**Data Flow:** Invoice creation → Database → PDF generation → Object storage → Download link

**The bug:** Invoices were created with sequential IDs and stored with the same ID as the filename. The PDF download endpoint at `/invoices/{id}/download` checked authentication but not authorization — any authenticated user could download any invoice by changing the ID.

**Impact:** Any user could download any other user's invoices, revealing billing addresses, payment methods, and business relationships.

**Root cause:** The service layer retrieved the invoice by ID without checking `owner_id`.

**Fix:** Added `AND owner_id = current_user_id` to the invoice retrieval query.

### Example 2: The GraphQL Admin Leak

**Target:** A project management SaaS
**Data Flow:** GraphQL resolver chain → Database → JSON response

**The bug:** The `users` query in GraphQL had no resolver-level authorization. An unauthenticated GraphQL query `{ users { email role projects { name } } }` returned all users and their project data from all organizations.

**Impact:** Complete user database + project mapping accessible without authentication.

**Root cause:** The GraphQL resolver for `users` returned the entire `SELECT * FROM users` without a filter.

**Fix:** Added resolver-level authorization that checks the user's organization scope and denies unauthenticated requests.

### Example 3: The Shared Cache IDOR

**Target:** A social media platform
**Data Flow:** API response → CDN cache → Cached response served to other users

**The bug:** The user profile API endpoint `GET /api/users/{id}/profile` returned private data but was cached by Cloudflare. When User A viewed User B's profile, the response was cached. When User C requested the same URL, they received User A's cached view (which included User A's private data).

**Impact:** User A's private profile data (including email, phone, and birthdate) was served to other users.

**Root cause:** The cache key didn't include the requesting user's ID, so cached responses were served across users.

**Fix:** Added `Vary: Cookie` or `Vary: Authorization` header, or made the cache key user-specific.

### Example 4: The WebSocket Data Flood

**Target:** A customer support chat application
**Data Flow:** WebSocket connection → Message broker → Push to connected clients

**The bug:** The WebSocket server authenticated at connection time but broadcast all messages to all connected clients. There was no per-channel or per-user message filtering.

**Impact:** Every connected user received every message from every conversation, including support tickets with PII from all customers.

**Root cause:** The message broker pushed all messages to all WebSocket connections without filtering by channel subscription.

**Fix:** Added per-channel subscriptions and message filtering on the server side.

### Example 5: The CSV Export Data Dump

**Target:** A CRM platform
**Data Flow:** Export request → CSV generation → Download link → Browser download

**The bug:** The export endpoint at `/api/contacts/export.csv` generated a CSV of ALL contacts in the organization, not just the current user's contacts. The authorization check only verified that the user was authenticated, not that they had permission to export all contacts.

**Impact:** Any user could download the entire contact database, including contacts they didn't own.

**Root cause:** The export query was `SELECT * FROM contacts WHERE org_id = ?` when it should have been `SELECT * FROM contacts WHERE owner_id = ?`.

**Fix:** Changed the query to scope by `owner_id` instead of `org_id`, and added a separate admin export endpoint with stricter controls.

---

## Checklist

### Pre-Mapping

- [ ] Catalog all API endpoints that accept or return user data
- [ ] Identify authentication mechanism (JWT, session cookie, API key)
- [ ] Identify authorization mechanism (RBAC, ABAC, ownership-based)
- [ ] List all user roles and their permissions
- [ ] Identify multi-tenancy model (shared DB, separate DB, sharded)

### Phase 1: Entry Points

- [ ] Map all REST endpoints with user data
- [ ] Map all GraphQL queries and mutations
- [ ] Map all WebSocket channels
- [ ] Map all file upload endpoints
- [ ] Map all export/download endpoints
- [ ] Map all webhook/callback endpoints
- [ ] Map all OAuth/SSO callback endpoints
- [ ] Identify batch/bulk operation endpoints

### Phase 2: Storage

- [ ] Identify database tables with user data
- [ ] Check for tenant column (user_id, owner_id, account_id)
- [ ] Check cache key patterns for user scoping
- [ ] Check queue message structure for user context
- [ ] Check object storage key patterns for user scoping
- [ ] Check search index for tenant partitioning
- [ ] Check logging for user data leakage

### Phase 3: Retrieval

- [ ] Test direct object access with other users' IDs
- [ ] Test list endpoints with parameter injections
- [ ] Test search endpoints for cross-user results
- [ ] Test export endpoints for scope bypass
- [ ] Test admin endpoints for horizontal access
- [ ] Test GraphQL resolvers for unfiltered access
- [ ] Test WebSocket channels for cross-user messages
- [ ] Test SSE endpoints for subscription bypass
- [ ] Test cache for cross-user response serving

### Phase 4: Checkpoints

- [ ] Map authorization checkpoints in the data flow
- [ ] Test API gateway auth bypass
- [ ] Test service layer ownership checks
- [ ] Test database RLS/views
- [ ] Test ORM query construction
- [ ] Test async worker authorization
- [ ] Test caching layer authorization

### Anti-Patterns

- [ ] Test UUID-based resources for access control
- [ ] Test mass assignment vectors
- [ ] Test CORS configurations with data flow vulnerabilities
- [ ] Test Referer header leakage
- [ ] Test WebSocket channel subscription authorization
- [ ] Test error message information disclosure
- [ ] Test timing side channels for resource existence
- [ ] Test cache-based data leakage
- [ ] Test signed URL access across users
- [ ] Test pre-signed upload URL scoping

### Reporting

- [ ] Document the complete data flow diagram for each finding
- [ ] Identify the exact checkpoint where isolation fails
- [ ] Provide a clear fix recommendation (specific code change)
- [ ] Estimate impact scope (number of affected users, data types leaked)
- [ ] Include reproducing steps that another tester can follow
- [ ] Attach proof of concept (request/response pairs, curl commands)
- [ ] Check against duplicate database before submission
- [ ] Run through the 7-Question Gate (see `triage-validation/SKILL-1.md`)

---

## Reference

- [OWASP Data Flow Analysis](https://owasp.org/www-community/Data_Flow_Analysis)
- [OWASP Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Improper_Authorization)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [PortSwigger IDOR Research](https://portswigger.net/web-security/access-control/idor)
- See also: `agents/idor-hunter.md`, `agents/api-misconfig-hunter.md`, `rules/scope.md`
