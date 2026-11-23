-- Мессенджер: настройка Supabase. Вставьте весь файл в SQL Editor и нажмите Run.

-- Профили (логин и имя)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null check (username ~ '^[a-z0-9_]{3,20}$'),
  name text not null,
  created_at timestamptz default now()
);

-- Сообщения
create table if not exists public.messages (
  id bigint generated always as identity primary key,
  sender uuid not null references public.profiles(id) on delete cascade,
  receiver uuid not null references public.profiles(id) on delete cascade,
  body text not null default '' check (char_length(body) <= 4000),
  image text,
  seen boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists messages_sender_idx on public.messages(sender, created_at desc);
create index if not exists messages_receiver_idx on public.messages(receiver, created_at desc);

-- Профиль создаётся автоматически при регистрации
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, username, name)
  values (
    new.id,
    lower(new.raw_user_meta_data->>'username'),
    coalesce(nullif(new.raw_user_meta_data->>'name', ''), new.raw_user_meta_data->>'username')
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Права доступа (Row Level Security)
alter table public.profiles enable row level security;
alter table public.messages enable row level security;

drop policy if exists "profiles read" on public.profiles;
create policy "profiles read" on public.profiles for select to authenticated using (true);
drop policy if exists "profiles update own" on public.profiles;
create policy "profiles update own" on public.profiles for update to authenticated using (id = auth.uid());

drop policy if exists "messages read own" on public.messages;
create policy "messages read own" on public.messages for select to authenticated
  using (sender = auth.uid() or receiver = auth.uid());
drop policy if exists "messages send" on public.messages;
create policy "messages send" on public.messages for insert to authenticated
  with check (sender = auth.uid());
drop policy if exists "messages mark seen" on public.messages;
create policy "messages mark seen" on public.messages for update to authenticated
  using (receiver = auth.uid());
-- Доступ к таблицам через API для вошедших пользователей
grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;
grant update (name) on public.profiles to authenticated;
grant select, insert on public.messages to authenticated;
-- менять в сообщениях можно только отметку «прочитано»
grant update (seen) on public.messages to authenticated;

-- Сообщения в реальном времени
do $$ begin
  alter publication supabase_realtime add table public.messages;
exception when duplicate_object then null; end $$;

-- Хранилище картинок
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('images', 'images', true, 15728640, array['image/jpeg','image/png','image/webp','image/gif'])
on conflict (id) do nothing;

drop policy if exists "images upload own folder" on storage.objects;
create policy "images upload own folder" on storage.objects for insert to authenticated
  with check (bucket_id = 'images' and (storage.foldername(name))[1] = auth.uid()::text);
