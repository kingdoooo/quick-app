CREATE TABLE IF NOT EXISTS expenses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  amount NUMERIC(10,2) NOT NULL,
  spender TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
