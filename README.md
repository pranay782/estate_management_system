# EstatePro – Real Estate Management System

A Flask + MongoDB real-estate management website with:
- Luxury navy/gold UI
- Property search and details
- Client/agent management
- Inquiries and appointments
- Admin dashboard
- User role/status management
- CSV property report
- Compatibility with existing `real_estate_database` collections

## Run

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
py -3.12 -m pip install -r requirements.txt
py app.py
```

Open http://127.0.0.1:5000

## MongoDB

Default:
`mongodb://localhost:27017/`

Database:
`real_estate_database`

Collections used:
`admin`, `appointments`, `favorites`, `inquiries`, `properties`, `receipts`, `transactions`, `users`, `clients`, `agents`

The application accepts both string IDs such as `PROP001` / `ADM010` and normal MongoDB ObjectIds.

## Admin

If an active Admin user already exists in `users`, use that account.

For a new local database, the app creates:
- Email: `admin@estatepro.com`
- Username: `admin`
- Password: `admin123`

Change the password after first login.
