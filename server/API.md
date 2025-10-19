# Tatou API Documentation

Complete API reference for the Tatou document watermarking platform.

---

## Table of Contents

### Health & General
- [healthz](#healthz) — **GET** `/healthz` — Check server health

### Authentication
- [create-user](#create-user) — **POST** `/api/create-user` — Create new user account
- [login](#login) — **POST** `/api/login` — Authenticate and get token

### Document Management
- [upload-document](#upload-document) — **POST** `/api/upload-document` — Upload a PDF document
- [list-documents](#list-documents) — **GET** `/api/list-documents` — List user's documents
- [get-document](#get-document) — **GET** `/api/get-document` — Retrieve a document
- [delete-document](#delete-document) — **DELETE** `/api/delete-document` — Delete a document

### Watermarking
- [get-watermarking-methods](#get-watermarking-methods) — **GET** `/api/get-watermarking-methods` — List available methods
- [create-watermark](#create-watermark) — **POST** `/api/create-watermark` — Create watermarked version
- [read-watermark-by-link](#read-watermark-by-link) — **POST** `/api/read-watermark-by-link/<link>` — Read watermark
- [list-versions](#list-versions) — **GET** `/api/list-versions` — List document versions
- [list-all-versions](#list-all-versions) — **GET** `/api/list-all-versions` — List all versions
- [get-version](#get-version) — **GET** `/api/get-version/<link>` — Download watermarked version

### RMAP Protocol
- [rmap-initiate](#rmap-initiate) — **POST** `/api/rmap-initiate` — Initiate RMAP session
- [rmap-get-link](#rmap-get-link) — **POST** `/api/rmap-get-link` — Get watermarked link via RMAP
- [rmap-identify-leak](#rmap-identify-leak) — **POST** `/api/rmap-identify-leak` — Identify document leaker (Admin only)

---

# API Reference



## healthz

**Path**  
`GET /healthz`

**Description**  
This endpoint checks the health of the server and confirms it is running. It also verifies database connectivity.

**Authentication**  
Not required

**Parameters**  
_None_

**Response Codes**
- `200` — Success (server is up, with or without DB connection)

**Return**
```json
{
  "message": "<string>",
  "db_connected": <boolean>
}
```

**Specification**
* The healthz endpoint MUST be accessible without authentication.
* The response MUST always contain a "message" field of type string.
* The response MUST indicate database connection status with a "db_connected" boolean field.
* The endpoint MUST return 200 even if database connection fails.

## create-user

**Path**  
`POST /api/create-user`

**Description**  
This endpoint creates a new user account in the system.

**Authentication**  
Not required

**Parameters**
```json
{
  "login": "<string>",
  "password": "<string>",
  "email": "<email>"
}
```

**Response Codes**
- `201` — User successfully created
- `400` — Missing or invalid required fields
- `409` — User with this email or login already exists
- `503` — Database error

**Return**
```json
{
  "id": <int>,
  "login": "<string>",
  "email": "<email>"
}
```

**Specification**
* The create-user endpoint MUST validate that username, password, and email are provided.
* All fields (login, password, email) MUST be non-empty strings.
* The response MUST include a unique id along with the created username and email.
* Email addresses MUST be unique in the system.
* Passwords MUST be securely hashed before storage.


## login

**Path**  
`POST /api/login`

**Description**  
This endpoint authenticates a user with their credentials and returns a session token.

**Authentication**  
Not required

**Parameters**
```json
{
  "email": "<string>",
  "password": "<string>"
}
```

**Response Codes**
- `200` — Login successful, token returned
- `400` — Missing required fields (email or password)
- `401` — Invalid credentials
- `503` — Database error

**Return**
```json
{
  "token": "<string>",
  "token_type": "bearer",
  "expires_in": <int>
}
```

**Specification**
* The login endpoint MUST reject requests missing email or password.
* The response MUST include a token string and its expiration date as an integer Time To Live in seconds.
* Invalid credentials MUST return 401 status code.
* The token MUST be used in the Authorization header as "Bearer <token>" for authenticated endpoints.

## upload-document

**Path**  
`POST /api/upload-document`

**Description**  
This endpoint uploads a PDF document to the server and registers its metadata.

**Authentication**  
Required (Bearer token in Authorization header)

**Parameters**  
Multipart form data:
- `file` — PDF file to upload
- `name` — Document name (string)

**Response Codes**
- `201` — Document successfully uploaded
- `400` — Missing file or name, or invalid file format
- `401` — Authentication required or invalid token
- `503` — Database error

**Return**
```json
{
  "id": <int>,
  "name": "<string>",
  "creation": "<date ISO 8601>",
  "sha256": "<string>",
  "size": <int>
}
```

**Specification**
* Requires authentication via Bearer token.
* The upload-document endpoint MUST accept only files in PDF format.
* The endpoint MUST calculate and store the SHA-256 hash of the uploaded file.
* Documents MUST be stored in a user-specific directory.
* The response MUST include document metadata: id, name, creation timestamp, sha256 hash, and size in bytes.

## list-documents

**Path**  
`GET /api/list-documents`

**Description**  
This endpoint lists all uploaded PDF documents owned by the authenticated user along with their metadata.

**Authentication**  
Required (Bearer token in Authorization header)

**Parameters**  
_None_

**Response Codes**
- `200` — Success, returns list of documents
- `401` — Authentication required or invalid token
- `503` — Database error

**Return**
```json
{
  "documents": [
    {
      "id": <int>,
      "name": "<string>",
      "creation": "<date ISO 8601>",
      "sha256": "<string>",
      "size": <int>
    }
  ]
}
```

**Specification**
* Requires authentication via Bearer token.
* The response MUST return all documents owned by the authenticated user.
* Documents from other users MUST NOT be included in the response.
* Returns an empty array if the user has no documents.

## list-versions

**Description**  
This endpoint lists all watermarked versions of a given PDF document along with their metadata.

**Authentication**  
Required (Bearer token in Authorization header)

**Paths**  
- `GET /api/list-versions?documentid=<int>`
- `GET /api/list-versions/<int:document_id>`

**Parameters**  
For first variant: Query parameter `documentid` (integer)  
For second variant: Path parameter `document_id` (integer)

**Response Codes**
- `200` — Success, returns list of versions
- `400` — Invalid or missing document ID
- `401` — Authentication required or invalid token
- `404` — Document not found
- `503` — Database error

**Return**
```json
{
  "versions": [
    {
      "id": <int>,
      "documentid": <int>,
      "link": "<string>",
      "intended_for": "<string>",
      "secret": "<string>",
      "method": "<string>"
    }
  ]
}
```

**Specification**
* Requires authentication via Bearer token.
* MUST only return versions for documents owned by the authenticated user.
* Returns an empty array if no versions exist for the document.


## list-all-versions

**Path**  
`GET /api/list-all-versions`

**Description**  
This endpoint lists all watermarked versions across all PDF documents owned by the authenticated user.

**Authentication**  
Required (Bearer token in Authorization header)

**Parameters**  
_None_

**Response Codes**
- `200` — Success, returns list of all versions
- `401` — Authentication required or invalid token
- `503` — Database error

**Return**
```json
{
  "versions": [
    {
      "id": <int>,
      "documentid": <int>,
      "link": "<string>",
      "intended_for": "<string>",
      "secret": "<string>",
      "method": "<string>"
    }
  ]
}
```

**Specification**
* Requires authentication via Bearer token.
* MUST return all versions for all documents owned by the authenticated user.
* Returns an empty array if no versions exist.

## get-document

**Description**  
This endpoint retrieves a PDF document by its ID. The document is returned as an inline binary file.

**Authentication**  
Required (Bearer token in Authorization header)

**Paths**  
- `GET /api/get-document?id=<int>`
- `GET /api/get-document/<int:document_id>`

**Parameters**  
For first variant: Query parameter `id` (integer)  
For second variant: Path parameter `document_id` (integer)

**Response Codes**
- `200` — Success, returns PDF file
- `400` — Invalid or missing document ID
- `401` — Authentication required or invalid token
- `404` — Document not found or not owned by user
- `410` — Document record exists but file missing from disk
- `500` — File system error or path security violation
- `503` — Database error

**Return**  
Binary PDF file with `Content-Type: application/pdf` and `Content-Disposition: inline`

**Specification**
* Requires authentication via Bearer token.
* MUST only allow document owner to retrieve the document.
* MUST prevent path traversal attacks and ensure secure file access.
* Documents from other users MUST return 404 to prevent information disclosure.

## delete-document

**Description**  
This endpoint deletes a document and all its associated watermarked versions from the system.

**Authentication**  
Required (Bearer token in Authorization header)

**Paths**  
- `DELETE /api/delete-document?id=<int>`
- `DELETE /api/delete-document/<int:document_id>`
- `POST /api/delete-document` (with id in body)

**Parameters**  
For first variant: Query parameter `id` (integer)  
For second variant: Path parameter `document_id` (integer)  
For third variant: JSON body with `id` field

**Response Codes**
- `200` — Document successfully deleted
- `400` — Invalid or missing document ID
- `401` — Authentication required or invalid token
- `404` — Document not found or not owned by user
- `503` — Database error

**Return**
```json
{
  "message": "<string>",
  "deleted_document_id": <int>
}
```

**Specification**
* Requires authentication via Bearer token.
* MUST only allow document owner to delete their documents.
* MUST delete all associated watermarked versions and their files.
* MUST clean up files from the file system.
* If file is already missing from disk, deletion should still succeed (200).

## get-watermarking-methods

**Description**  
This endpoint lists all available watermarking methods that can be used to create watermarked documents.

**Authentication**  
Not required

**Path**  
`GET /api/get-watermarking-methods`

**Parameters**  
_None_

**Response Codes**
- `200` — Success, returns list of methods

**Return**
```json
{
  "count": <int>,
  "methods": [
    {
      "name": "<string>",
      "description": "<string>"
    }
  ]
}
```

**Specification**
* The endpoint MUST return all methods defined in `watermarking_utils.METHODS`.
* Each method MUST include a name and description.

## read-watermark-by-link

**Description**  
Read and extract the watermark from a specific watermarked version identified by its link.

**Authentication**  
Required (Bearer token in Authorization header)

**Path**  
`POST /api/read-watermark-by-link/<link>`

**Parameters**  
Path: `link` — The unique link identifier for the watermarked version  
JSON body:
```json
{
  "method": "<string>",
  "position": "<string>",
  "key": "<string>"
}
```

**Response Codes**
- `200` — Success, watermark extracted
- `400` — Invalid parameters, watermark extraction failed, or secret mismatch
- `401` — Authentication required or invalid token
- `404` — Version with this link not found
- `410` — Version record exists but file missing from disk
- `500` — File system error or path security violation
- `503` — Database error

**Return**
```json
{
  "link": "<string>",
  "secret": "<string>",
  "method": "<string>",
  "position": "<string>"
}
```

**Specification**
* Requires authentication via Bearer token.
* The endpoint MUST extract and return the secret embedded in the document.
* MUST verify that the extracted secret matches the stored secret.
* MUST only allow the document owner to read watermarks.


## create-watermark

**Description**  
This endpoint creates a watermarked version of a PDF document with the specified watermarking method and parameters.

**Authentication**  
Required (Bearer token in Authorization header)

**Paths**  
- `POST /api/create-watermark` (with `id` in body)
- `POST /api/create-watermark/<int:document_id>`

**Parameters**  
For first variant — JSON body:
```json
{
  "id": <int>,
  "method": "<string>",
  "position": "<string>",
  "key": "<string>",
  "secret": "<string>",
  "intended_for": "<string>"
}
```

For second variant — JSON body (document_id from path):
```json
{
  "method": "<string>",
  "position": "<string>",
  "key": "<string>",
  "secret": "<string>",
  "intended_for": "<string>"
}
```

**Response Codes**
- `201` — Watermarked version successfully created
- `400` — Missing required fields or method not applicable to document
- `401` — Authentication required or invalid token
- `404` — Document not found or not owned by user
- `500` — Watermarking process failed or file write error
- `503` — Database error

**Return**
```json
{
  "id": <int>,
  "documentid": <int>,
  "link": "<string>",
  "intended_for": "<string>",
  "method": "<string>",
  "position": "<string>",
  "filename": "<string>",
  "size": <int>
}
```

**Specification**
* Requires authentication via Bearer token.
* Only the owner of a document MUST be able to create watermarked versions.
* The document owner MUST be able to list all versions and their intended recipients.
* MUST validate that the watermarking method is applicable to the document.
* MUST generate a unique, unguessable link for each watermarked version.
* The secret MUST be embedded in the watermarked document.
* If watermarking fails or produces empty output, MUST return appropriate error.

## get-version

**Description**  
Download a watermarked version of a document by its unique link. This endpoint does not require authentication - anyone with the link can download.

**Authentication**  
Not required (access controlled by knowledge of the link)

**Path**  
`GET /api/get-version/<link>`

**Parameters**  
Path: `link` — The unique link identifier for the watermarked version

**Response Codes**
- `200` — Success, returns watermarked PDF file
- `404` — Version with this link not found
- `500` — File system error or path security violation
- `503` — Database error

**Return**  
Binary PDF file with `Content-Type: application/pdf` and `Content-Disposition: inline`

**Specification**
* Authentication is NOT required - access is granted by knowledge of the link.
* The link MUST be unguessable to prevent unauthorized access.
* A watermarked document MAY be downloaded by anyone having knowledge of the link.
* MUST prevent path traversal attacks and ensure secure file access.

## rmap-initiate

**Description**  
This endpoint initiates the RMAP (Robust Messaging Authentication Protocol) session by receiving GPG encrypted message 1.

**Authentication**  
Not required (uses GPG encryption for authentication)

**Path**  
`POST /api/rmap-initiate`

**Parameters**  
JSON body:
```json
{
  "payload": "<ASCII_armored_base64>"
}
```

The encrypted payload should decrypt to:
```json
{
  "nonceClient": <u64>,
  "identity": "<string>"
}
```

**Response Codes**
- `200` — Success, returns encrypted response
- `400` — Invalid payload or unknown identity
- `500` — Server error during encryption/decryption

**Return**  
JSON body:
```json
{
  "payload": "<ASCII_armored_base64>"
}
```

The encrypted response decrypts to:
```json
{
  "nonceClient": <u64>,
  "nonceServer": <u64>
}
```

**Specification**
* The server SHOULD only respond to known identities.
* All submitted group public keys MUST constitute valid identities.
* The server MUST verify the GPG signature and decrypt the message.
* The server MUST generate a unique nonceServer for the session.
* The response MUST be encrypted with the client's public key and signed with the server's private key.
 
## rmap-get-link

**Description**  
This endpoint completes the RMAP protocol by receiving GPG encrypted message 2 and returning a link to the group-specific watermarked document.

**Authentication**  
Not required (uses GPG encryption + nonce verification for authentication)

**Path**  
`POST /api/rmap-get-link`

**Parameters**  
JSON body:
```json
{
  "payload": "<ASCII_armored_base64>"
}
```

The encrypted payload should decrypt to:
```json
{
  "nonceServer": <u64>
}
```

**Response Codes**
- `200` — Success, returns encrypted link
- `400` — Invalid payload, nonce mismatch, or session not found
- `404` — Source document not found
- `500` — Watermarking error or file operation failed
- `503` — Database error

**Return**  
JSON body:
```json
{
  "payload": "<ASCII_armored_base64>"
}
```

The encrypted response decrypts to:
```json
{
  "result": "<32-hex NonceClient||NonceServer>"
}
```

**Specification**
* `get-version/<result>` SHOULD point to a watermarked version of a PDF specific to the group authenticated by the public key of the client.
* The server MUST verify the nonceServer matches the one from the initiate phase.
* If a watermarked version for this identity doesn't exist, the server MUST create it.
* The watermark MUST be specific to the authenticated group/identity.
* The link (result) MUST be the hash of NonceClient||NonceServer.
* MUST clean up files if database insertion fails.

## rmap-identify-leak

**Description**  
This endpoint extracts watermarks from a submitted PDF file to identify which group/identity the file was originally distributed to. This is used to identify document leakers.

**Authentication**  
Required (Admin key via `X-Admin-Key` header or `admin_key` form field)

**Path**  
`POST /api/rmap-identify-leak`

**Headers**  
- `X-Admin-Key` — Admin authentication key (optional if provided in form data)

**Parameters**  
Multipart form data:
- `file` — PDF file to analyze
- `admin_key` — Admin key (alternative to header)

**Response Codes**
- `200` — Success, watermark identified (or not found)
- `400` — Missing file or invalid request
- `401` — Unauthorized (invalid or missing admin key)
- `404` — Watermark extracted but no matching version found in database
- `503` — Database error

**Return**  

Success (watermark identified):
```json
{
  "identified": true,
  "identity": "<string>",
  "extracted_secret": "<string>",
  "method": "<string>",
  "version_info": {
    "id": <int>,
    "link": "<string>",
    "intended_for": "<string>",
    "path": "<string>"
  }
}
```

Watermark extraction failed:
```json
{
  "identified": false,
  "error": "<string>"
}
```

Unauthorized:
```json
{
  "error": "Unauthorized"
}
```

**Specification**
* The endpoint MUST require admin authentication via `X-Admin-Key` header or `admin_key` form field.
* The endpoint MUST attempt to extract the watermark using the configured watermarking method.
* If successful, it MUST return the identified group/identity.
* The endpoint MUST query the database to find the matching version record.
* Unauthorized access attempts MUST return 401 status code.
* Admin key validation MUST be secure and not expose timing attacks.

---

## Notes

### Authentication
All endpoints marked as requiring authentication use Bearer token authentication via the `Authorization` header:
```
Authorization: Bearer <token>
```

Tokens are obtained via the `/api/login` endpoint and have a limited lifetime specified by the `expires_in` field.

### Error Handling
All endpoints return consistent error responses in JSON format:
```json
{
  "error": "<error message>"
}
```

### Security
- Path traversal attacks are prevented on all file operations
- Authentication tokens expire after the specified TTL
- Watermark links are cryptographically random and unguessable
- Admin endpoints require separate admin key authentication
- GPG encryption is used for RMAP protocol security

### RMAP Protocol Flow
1. Client calls `/api/rmap-initiate` with encrypted identity and nonceClient
2. Server responds with encrypted nonceClient and nonceServer
3. Client calls `/api/rmap-get-link` with encrypted nonceServer
4. Server creates watermark if needed and returns link (hash of nonces)
5. Client can download watermarked PDF via `/api/get-version/<link>`

---

**Last Updated**: October 19, 2025  
**API Version**: 1.0
