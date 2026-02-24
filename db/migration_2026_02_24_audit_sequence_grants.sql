-- Run as a DB admin user.
-- Replace __APP_DB_ROLE__ with the role used by the backend application.

GRANT INSERT, SELECT ON TABLE audit_events TO __APP_DB_ROLE__;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO __APP_DB_ROLE__;

GRANT INSERT, SELECT ON TABLE audit_logins TO __APP_DB_ROLE__;
GRANT USAGE, SELECT ON SEQUENCE audit_logins_id_seq TO __APP_DB_ROLE__;
