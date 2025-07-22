# Multi-State Address API

An address autocomplete API for Ohio and Texas (more to come), powered by SmartyStreets with Nominatim and default fallback providers.

## Quick Start

### Get Address Suggestions
```bash
GET https://vercelsmartyapi.vercel.app/api/address-suggestions?query=123%20Main&state=TX
```

### Response
```json
{
  "success": true,
  "addresses": [
    {
      "fullAddress": "123 Main St, Houston, TX 77001",
      "address": "123 Main St",
      "city": "Houston",
      "state": "TX",
      "zipcode": "77001",
      "verified": true,
      "confidence": "high"
    }
  ]
}
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/address-suggestions` | Main address search (supports `?state=OH` or `?state=TX`) |
| `/api/texas-address-suggestions` | Texas-specific search |
| `/api/health` | API status and configuration |

## Parameters

- `query` - Address to search for (required, min 2 chars)
- `state` - State code: `OH` or `TX` (default: `OH`)
- `limit` - Max results: 1-15 (default: 5)

## Environment Variables

```bash
SMARTYSTREETS_AUTH_ID=your_auth_id
SMARTYSTREETS_AUTH_TOKEN=your_auth_token
```

## Features

SmartyStreets integration for verified addresses  
Nominatim backup for additional coverage  
Smart fallback system  
Built iin caching  
Rate limiting  
CORS enabled 
