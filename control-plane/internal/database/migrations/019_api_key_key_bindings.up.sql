ALTER TABLE api_keys
ADD COLUMN IF NOT EXISTS allowed_key_ids UUID[];

COMMENT ON COLUMN api_keys.allowed_key_ids IS 'Keys this API key may use; NULL or empty means every key in the organization';
