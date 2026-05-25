-- Add public key column for E2EE (hybrid encryption)
ALTER TABLE agents ADD COLUMN public_key_pem TEXT;
