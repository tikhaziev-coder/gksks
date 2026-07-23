-- ============================================================
-- Академия СКС · Авторизация: таблица профилей + права доступа
-- Выполнить ОДИН РАЗ в Supabase: SQL Editor → New query → вставить → Run
-- ============================================================

-- 1. Таблица профилей (ФИО, почта, дата регистрации)
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  full_name  text not null default '',
  email      text not null default '',
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- 2. Автозаполнение профиля при регистрации нового пользователя
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, email)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    coalesce(new.email, '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 3. Кто админ (видит полный список зарегистрированных)
create or replace function public.is_admin()
returns boolean
language sql stable
as $$
  select coalesce(auth.jwt()->>'email','') = 'ti.khaziev@gmail.com'
$$;

-- 4. Правила чтения: каждый видит свой профиль, админ — всех
drop policy if exists "profiles read" on public.profiles;
create policy "profiles read" on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

-- 5. Хранилище статей: у вошедших пользователей роль меняется
--    с anon на authenticated — дублируем права, иначе библиотека
--    перестанет работать после входа.
drop policy if exists "kb auth read" on storage.objects;
create policy "kb auth read" on storage.objects
  for select to authenticated using (bucket_id = 'Kb');

drop policy if exists "kb auth upload" on storage.objects;
create policy "kb auth upload" on storage.objects
  for insert to authenticated with check (bucket_id = 'Kb');
