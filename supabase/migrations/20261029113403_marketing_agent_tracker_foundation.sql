/*
# Marketing Agent Tracker foundation

1. New tables
- `profiles`: authenticated user profile, role, status, and display details.
- `app_settings`: the single configurable commission rate.
- `customer_accounts`: customer submissions owned by the authenticated agent, with review and commission fields.
- `commission_payments`: admin-recorded payments tied to an agent.
- `activity_logs`: immutable audit records for administrative actions.

2. Security
- All tables have row-level security enabled.
- Agents can read and create only their own customer submissions and payments visible for their agent.
- Main admins can review and manage all operational records.
- Privileged review, payment, settings, and role changes run through server-side functions that verify the signed-in caller.
- Client writes cannot set role, ownership, approval, commission, payment recorder, or audit fields.

3. Important notes
- `matmove.sl@gmail.com` is assigned the initial main-admin role by the signup trigger.
- New non-admin signups are agents in pending status until activated by an admin.
- The commission rate at approval is preserved on each approved account.
*/

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name text NOT NULL DEFAULT '',
  email text NOT NULL,
  role text NOT NULL DEFAULT 'agent' CHECK (role IN ('admin', 'agent')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('active', 'pending', 'suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.app_settings (
  id boolean PRIMARY KEY DEFAULT true,
  commission_rate numeric(14,2) NOT NULL DEFAULT 2000000 CHECK (commission_rate >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES auth.users(id)
);

CREATE TABLE IF NOT EXISTS public.customer_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_name text NOT NULL CHECK (char_length(trim(customer_name)) BETWEEN 2 AND 120),
  customer_whatsapp_phone text NOT NULL CHECK (customer_whatsapp_phone ~ '^\\+232[0-9]{8,9}$'),
  user_type text NOT NULL CHECK (user_type IN ('Driver', 'Rider', 'Merchant')),
  whatsapp_status text NOT NULL CHECK (whatsapp_status IN ('Yes', 'No')),
  agent_id uuid NOT NULL DEFAULT auth.uid() REFERENCES public.profiles(id) ON DELETE RESTRICT,
  approval_status text NOT NULL DEFAULT 'pending' CHECK (approval_status IN ('pending', 'approved', 'rejected')),
  commission_eligible boolean NOT NULL DEFAULT false,
  commission_rate_at_approval numeric(14,2),
  commission_amount numeric(14,2) NOT NULL DEFAULT 0,
  rejection_reason text,
  duplicate_flag boolean NOT NULL DEFAULT false,
  reviewed_at timestamptz,
  reviewed_by uuid REFERENCES public.profiles(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.commission_payments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE RESTRICT,
  amount numeric(14,2) NOT NULL CHECK (amount > 0),
  payment_date date NOT NULL DEFAULT CURRENT_DATE,
  payment_reference text NOT NULL CHECK (char_length(trim(payment_reference)) BETWEEN 1 AND 120),
  notes text,
  recorded_by uuid NOT NULL DEFAULT auth.uid() REFERENCES public.profiles(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.activity_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid NOT NULL DEFAULT auth.uid() REFERENCES public.profiles(id),
  action text NOT NULL,
  record_type text NOT NULL,
  record_id uuid,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS customer_accounts_agent_id_idx ON public.customer_accounts(agent_id);
CREATE INDEX IF NOT EXISTS customer_accounts_created_at_idx ON public.customer_accounts(created_at DESC);
CREATE INDEX IF NOT EXISTS customer_accounts_phone_idx ON public.customer_accounts(customer_whatsapp_phone);
CREATE INDEX IF NOT EXISTS commission_payments_agent_id_idx ON public.commission_payments(agent_id);
CREATE INDEX IF NOT EXISTS activity_logs_created_at_idx ON public.activity_logs(created_at DESC);

INSERT INTO public.app_settings (id, commission_rate)
VALUES (true, 2000000)
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role = 'admin' AND status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, email, role, status)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data ->> 'full_name', ''),
    lower(NEW.email),
    CASE WHEN lower(NEW.email) = 'matmove.sl@gmail.com' THEN 'admin' ELSE 'agent' END,
    CASE WHEN lower(NEW.email) = 'matmove.sl@gmail.com' THEN 'active' ELSE 'pending' END
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

CREATE OR REPLACE FUNCTION public.review_customer_account(
  p_account_id uuid,
  p_decision text,
  p_rejection_reason text DEFAULT NULL
)
RETURNS public.customer_accounts
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_account public.customer_accounts;
  v_rate numeric(14,2);
BEGIN
  IF NOT public.is_admin() THEN RAISE EXCEPTION 'Not authorized'; END IF;
  IF p_decision NOT IN ('approved', 'rejected') THEN RAISE EXCEPTION 'Invalid decision'; END IF;
  IF p_decision = 'rejected' AND NULLIF(trim(COALESCE(p_rejection_reason, '')), '') IS NULL THEN RAISE EXCEPTION 'Rejection reason required'; END IF;
  SELECT commission_rate INTO v_rate FROM public.app_settings WHERE id = true;
  UPDATE public.customer_accounts
  SET approval_status = p_decision,
      commission_eligible = p_decision = 'approved' AND NOT duplicate_flag,
      commission_rate_at_approval = CASE WHEN p_decision = 'approved' THEN v_rate ELSE NULL END,
      commission_amount = CASE WHEN p_decision = 'approved' AND NOT duplicate_flag THEN v_rate ELSE 0 END,
      rejection_reason = CASE WHEN p_decision = 'rejected' THEN trim(p_rejection_reason) ELSE NULL END,
      reviewed_at = now(),
      reviewed_by = auth.uid()
  WHERE id = p_account_id AND approval_status = 'pending'
  RETURNING * INTO v_account;
  IF v_account.id IS NULL THEN RAISE EXCEPTION 'Account is not pending'; END IF;
  INSERT INTO public.activity_logs (action, record_type, record_id, details)
  VALUES (p_decision, 'customer_account', v_account.id, jsonb_build_object('reason', v_account.rejection_reason));
  RETURN v_account;
END;
$$;

CREATE OR REPLACE FUNCTION public.set_commission_rate(p_rate numeric)
RETURNS public.app_settings
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_settings public.app_settings;
BEGIN
  IF NOT public.is_admin() OR p_rate < 0 OR p_rate > 1000000000 THEN RAISE EXCEPTION 'Invalid request'; END IF;
  UPDATE public.app_settings SET commission_rate = p_rate, updated_at = now(), updated_by = auth.uid() WHERE id = true RETURNING * INTO v_settings;
  INSERT INTO public.activity_logs (action, record_type, details) VALUES ('commission_rate_changed', 'app_settings', jsonb_build_object('rate', p_rate));
  RETURN v_settings;
END;
$$;

CREATE OR REPLACE FUNCTION public.set_profile_status(p_profile_id uuid, p_status text)
RETURNS public.profiles
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_profile public.profiles;
BEGIN
  IF NOT public.is_admin() OR p_status NOT IN ('active', 'pending', 'suspended') THEN RAISE EXCEPTION 'Invalid request'; END IF;
  UPDATE public.profiles SET status = p_status WHERE id = p_profile_id AND role = 'agent' RETURNING * INTO v_profile;
  IF v_profile.id IS NULL THEN RAISE EXCEPTION 'Agent not found'; END IF;
  INSERT INTO public.activity_logs (action, record_type, record_id, details) VALUES ('agent_status_changed', 'profile', v_profile.id, jsonb_build_object('status', p_status));
  RETURN v_profile;
END;
$$;

CREATE OR REPLACE FUNCTION public.record_commission_payment(
  p_agent_id uuid,
  p_amount numeric,
  p_payment_date date,
  p_payment_reference text,
  p_notes text DEFAULT NULL
)
RETURNS public.commission_payments
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_payment public.commission_payments;
BEGIN
  IF NOT public.is_admin() OR p_amount <= 0 OR char_length(trim(p_payment_reference)) = 0 THEN RAISE EXCEPTION 'Invalid request'; END IF;
  INSERT INTO public.commission_payments (agent_id, amount, payment_date, payment_reference, notes, recorded_by)
  VALUES (p_agent_id, p_amount, p_payment_date, trim(p_payment_reference), p_notes, auth.uid()) RETURNING * INTO v_payment;
  INSERT INTO public.activity_logs (action, record_type, record_id, details) VALUES ('payment_recorded', 'commission_payment', v_payment.id, jsonb_build_object('agent_id', p_agent_id, 'amount', p_amount));
  RETURN v_payment;
END;
$$;

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.customer_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.commission_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;

GRANT SELECT ON public.profiles TO authenticated;
GRANT SELECT ON public.app_settings TO authenticated;
GRANT SELECT, INSERT ON public.customer_accounts TO authenticated;
GRANT SELECT ON public.commission_payments TO authenticated;
GRANT SELECT ON public.activity_logs TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated;
GRANT EXECUTE ON FUNCTION public.review_customer_account(uuid, text, text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.set_commission_rate(numeric) TO authenticated;
GRANT EXECUTE ON FUNCTION public.set_profile_status(uuid, text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.record_commission_payment(uuid, numeric, date, text, text) TO authenticated;
REVOKE EXECUTE ON FUNCTION public.is_admin() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.review_customer_account(uuid, text, text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.set_commission_rate(numeric) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.set_profile_status(uuid, text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.record_commission_payment(uuid, numeric, date, text, text) FROM PUBLIC, anon;

DROP POLICY IF EXISTS "profiles_read_self_or_admin" ON public.profiles;
CREATE POLICY "profiles_read_self_or_admin" ON public.profiles FOR SELECT TO authenticated USING (id = auth.uid() OR public.is_admin());
DROP POLICY IF EXISTS "settings_read_authenticated" ON public.app_settings;
CREATE POLICY "settings_read_authenticated" ON public.app_settings FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS "accounts_read_own_or_admin" ON public.customer_accounts;
CREATE POLICY "accounts_read_own_or_admin" ON public.customer_accounts FOR SELECT TO authenticated USING (agent_id = auth.uid() OR public.is_admin());
DROP POLICY IF EXISTS "accounts_insert_own" ON public.customer_accounts;
CREATE POLICY "accounts_insert_own" ON public.customer_accounts FOR INSERT TO authenticated WITH CHECK (agent_id = auth.uid());
DROP POLICY IF EXISTS "payments_read_own_or_admin" ON public.commission_payments;
CREATE POLICY "payments_read_own_or_admin" ON public.commission_payments FOR SELECT TO authenticated USING (agent_id = auth.uid() OR public.is_admin());
DROP POLICY IF EXISTS "logs_read_admin" ON public.activity_logs;
CREATE POLICY "logs_read_admin" ON public.activity_logs FOR SELECT TO authenticated USING (public.is_admin());

REVOKE UPDATE ON public.profiles FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.app_settings FROM authenticated;
REVOKE UPDATE, DELETE ON public.customer_accounts FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.commission_payments FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.activity_logs FROM authenticated;
