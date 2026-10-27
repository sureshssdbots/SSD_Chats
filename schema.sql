-- Supabase > SQL Editor mein poora paste karke Run karo.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default 'User'
);
create table public.directory (
  id uuid primary key references auth.users(id) on delete cascade,
  enc_pub text not null, sig_pub text not null,
  updated_at timestamptz not null default now()
);
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender uuid not null default auth.uid() references auth.users(id) on delete cascade,
  recipient uuid not null references auth.users(id) on delete cascade,
  ts bigint not null, n text not null, iv text not null, ct text not null,
  wk_to text not null, wk_from text not null, sig text not null,
  created_at timestamptz not null default now(),
  constraint ct_size check (length(ct) < 20000)
);
create index on public.messages (sender);
create index on public.messages (recipient);

alter table public.profiles  enable row level security;
alter table public.directory enable row level security;
alter table public.messages  enable row level security;

create policy "profiles read"  on public.profiles  for select to authenticated using (true);
create policy "directory read" on public.directory for select to authenticated using (true);
create policy "directory add"  on public.directory for insert to authenticated with check (id = auth.uid());
create policy "directory edit" on public.directory for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- Messages: sirf sender aur recipient padh sakte hain. Sirf sender delete kar sakta hai.
create policy "msg read"   on public.messages for select to authenticated using (auth.uid() in (sender, recipient));
create policy "msg send"   on public.messages for insert to authenticated with check (sender = auth.uid() and recipient <> sender);
create policy "msg delete" on public.messages for delete to authenticated using (sender = auth.uid());

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name)
  values (new.id, left(coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)), 40));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

alter publication supabase_realtime add table public.messages, public.directory;
