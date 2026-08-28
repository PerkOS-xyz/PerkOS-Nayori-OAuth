CREATE TABLE agent_registrations (
  registration_id varchar(40) PRIMARY KEY,
  label varchar(80),
  challenge_id varchar(40) NOT NULL UNIQUE,
  claim_token_digest char(64) NOT NULL UNIQUE,
  user_code_digest char(64) NOT NULL,
  claim_expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  wallet_address varchar(64),
  public_key varchar(68),
  revoked_at timestamptz,
  last_polled_at timestamptz,
  last_token_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((claimed_at IS NULL AND wallet_address IS NULL AND public_key IS NULL) OR
         (claimed_at IS NOT NULL AND wallet_address IS NOT NULL AND public_key IS NOT NULL))
);

CREATE INDEX agent_registrations_claim_expiry_idx
  ON agent_registrations (claim_expires_at) WHERE claimed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX agent_registrations_wallet_idx
  ON agent_registrations (wallet_address) WHERE wallet_address IS NOT NULL AND revoked_at IS NULL;
