-- Run AFTER schema.sql. Adds unique usernames (@handles) and a key transparency log.

-- 1) Unique usernames
alter table public.profiles add column handle text;
update public.profiles p set handle =
  left(regexp_replace(lower(split_part(u.email, '@', 1)), '[^a-z0-9_]', '', 'g'), 12) || substr(md5(p.id::text), 1, 4)
from auth.users u where u.id = p.id and p.handle is null;
alter table public.profiles alter column handle set not null;
alter table public.profiles add constraint handle_format check (handle ~ '^[a-z0-9_]{3,20}$');
create unique index profiles_handle_key on public.profiles (handle);
create index profiles_handle_prefix on public.profiles (handle text_pattern_ops);

create function public.handle_available(h text) returns boolean
language sql security definer set search_path = public stable as
$$ select not exists (select 1 from public.profiles where handle = lower(h)) $$;
grant execute on function public.handle_available(text) to anon, authenticated;

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name, handle) values (
    new.id,
    left(coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)), 40),
    lower(coalesce(new.raw_user_meta_data->>'handle', split_part(new.email, '@', 1) || substr(md5(new.id::text), 1, 4)))
  );
  return new;
end $$;

-- 2) Key transparency: append-only, hash-chained key history per user
create extension if not exists pgcrypto with schema extensions;
create table public.key_log (
  seq bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  enc_pub text not null, sig_pub text not null,
  prev_hash text not null, hash text not null,
  created_at timestamptz not null default now()
);
create index on public.key_log (user_id, seq);
alter table public.key_log enable row level security;
create policy "log read" on public.key_log for select to authenticated using (true);
-- no insert/update/delete policy: clients can never edit the log

insert into public.key_log (user_id, enc_pub, sig_pub, prev_hash, hash)
select id, enc_pub, sig_pub, 'genesis',
  encode(extensions.digest('genesis|' || id::text || '|' || enc_pub || '|' || sig_pub, 'sha256'), 'hex')
from public.directory;

create function public.log_key_change() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare p text;
begin
  if tg_op = 'UPDATE' and new.enc_pub = old.enc_pub and new.sig_pub = old.sig_pub then return new; end if;
  perform pg_advisory_xact_lock(hashtext(new.id::text));
  select coalesce((select hash from key_log where user_id = new.id order by seq desc limit 1), 'genesis') into p;
  insert into key_log (user_id, enc_pub, sig_pub, prev_hash, hash) values (
    new.id, new.enc_pub, new.sig_pub, p,
    encode(digest(p || '|' || new.id::text || '|' || new.enc_pub || '|' || new.sig_pub, 'sha256'), 'hex'));
  return new;
end $$;
create trigger directory_log after insert or update on public.directory
  for each row execute function public.log_key_change();
