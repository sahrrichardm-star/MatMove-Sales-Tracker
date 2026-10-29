/*
# Mark possible duplicate customer submissions

1. Database change
- Adds a trigger function that marks a new customer account as a possible duplicate when the normalized WhatsApp number already exists.
- Duplicate records remain visible for admin review but start as non-commission-eligible.

2. Security
- The trigger runs inside PostgreSQL, so duplicate detection cannot be bypassed by changing the browser request.
- No records are deleted and no existing submission is modified.
*/

CREATE OR REPLACE FUNCTION public.mark_duplicate_customer_account()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  NEW.customer_whatsapp_phone := regexp_replace(NEW.customer_whatsapp_phone, '[^0-9+]', '', 'g');
  NEW.duplicate_flag := EXISTS (
    SELECT 1 FROM public.customer_accounts
    WHERE customer_whatsapp_phone = NEW.customer_whatsapp_phone
  );
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS before_customer_account_insert ON public.customer_accounts;
CREATE TRIGGER before_customer_account_insert
  BEFORE INSERT ON public.customer_accounts
  FOR EACH ROW EXECUTE FUNCTION public.mark_duplicate_customer_account();
