CREATE OR REPLACE FUNCTION public.provider_public_json_safe(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    member record;
    normalized text;
BEGIN
    IF jsonb_typeof(document) = 'object' THEN
        FOR member IN SELECT key, value FROM jsonb_each(document) LOOP
            normalized := regexp_replace(lower(member.key), '[^a-z0-9]', '', 'g');
            IF (NOT (normalized = ANY (ARRAY[
                    'preimagerecoveryref', 'credentialexposure'
                ])) AND (
                position('seed' IN normalized) > 0
                OR position('preimage' IN normalized) > 0
                OR position('privatekey' IN normalized) > 0
                OR position('spendkey' IN normalized) > 0
                OR position('claimkey' IN normalized) > 0
                OR position('refundkey' IN normalized) > 0
                OR position('macaroon' IN normalized) > 0
                OR position('credential' IN normalized) > 0
            ))
                OR normalized = ANY (ARRAY[
                'mnemonic', 'xprv', 'claimsecret', 'refundsecret',
                'nwc', 'nwcstring',
                'nwcconnectionstring', 'nwcuri', 'bearertoken',
                'walletrpcpayload', 'musigsecretnonce',
                'privkey', 'secretkey', 'secretnonce', 'signingnonce'
            ]) THEN
                RETURN false;
            END IF;
            IF NOT public.provider_public_json_safe(member.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(document) = 'array' THEN
        FOR member IN SELECT value FROM jsonb_array_elements(document) LOOP
            IF NOT public.provider_public_json_safe(member.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(document) = 'string' THEN
        normalized := document #>> '{}';
        IF normalized LIKE 'xprv%'
            OR normalized LIKE 'tprv%'
            OR normalized LIKE 'nostr+walletconnect://%'
        THEN
            RETURN false;
        END IF;
    END IF;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.provider_signed_event_safe(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    content jsonb;
BEGIN
    IF jsonb_typeof(document) <> 'object'
        OR jsonb_typeof(document -> 'content') <> 'string'
        OR NOT public.provider_public_json_safe(document)
    THEN
        RETURN false;
    END IF;
    BEGIN
        content := (document ->> 'content')::jsonb;
    EXCEPTION WHEN others THEN
        RETURN false;
    END;
    RETURN public.provider_public_json_safe(content);
END;
$$;
