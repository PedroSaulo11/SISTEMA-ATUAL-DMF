# TODO: Deploy DMF Application to Google Cloud

## Database Migration
- [x] Install PostgreSQL client library (pg)
- [x] Update webhook-server.js to use PostgreSQL instead of SQLite3
- [x] Create database schema for webhook_data table in PostgreSQL
- [ ] Update .env with PostgreSQL connection details

## Google Cloud Configuration
- [x] Create app.yaml for App Engine deployment
- [ ] Configure environment variables for production
- [ ] Set up Google Cloud SQL connection

## Deployment
- [ ] Test database connection locally
- [ ] Deploy to Google Cloud App Engine
- [ ] Verify webhook functionality with PostgreSQL
- [ ] Test Conta Azul API integration
- [ ] Update frontend to use production URLs

## Post-Deployment
- [ ] Configure domain (if needed)
- [ ] Set up monitoring and logging
- [ ] Test all endpoints
