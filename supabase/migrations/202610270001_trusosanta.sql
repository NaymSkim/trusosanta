-- Application tables live outside the Data API's public schema.
create schema if not exists trusosanta_private;
revoke all on schema trusosanta_private from public, anon, authenticated;

create table trusosanta_private.event (
  id integer primary key check (id = 1),
  status text not null default 'open' check (status in ('open','drawn','insufficient')),
  deadline timestamptz not null default '2026-11-05 16:19:00+00'
);
insert into trusosanta_private.event(id) values (1);
create table trusosanta_private.participants (
  id bigint generated always as identity primary key,
  key_hash text not null unique check (key_hash ~ '^[a-f0-9]{64}$'),
  name text not null check (length(name) between 1 and 60),
  size text not null check (length(size) between 1 and 40)
);
create table trusosanta_private.assignments (
  giver bigint primary key references trusosanta_private.participants(id),
  receiver bigint not null unique references trusosanta_private.participants(id),
  check (giver <> receiver)
);
alter table trusosanta_private.event enable row level security;
alter table trusosanta_private.participants enable row level security;
alter table trusosanta_private.assignments enable row level security;
revoke all on all tables in schema trusosanta_private from public, anon, authenticated;
revoke all on all sequences in schema trusosanta_private from public, anon, authenticated;

-- Only the Edge Function's server credential can call this entrypoint.
-- All actions lock the same event row, so writes and the draw are serialized.
create or replace function public.trusosanta_request(
  p_action text,
  p_key_hash text default null,
  p_name text default null,
  p_size text default null
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_event trusosanta_private.event%rowtype;
  v_person trusosanta_private.participants%rowtype;
  v_receiver trusosanta_private.participants%rowtype;
  v_now timestamptz;
  v_ids bigint[];
  v_count integer;
  v_state jsonb;
  v_result jsonb;
begin
  if p_action not in ('status','me','create','edit','delete') or p_action is null then
    return jsonb_build_object('code',400,'error','Некорректное действие.');
  end if;
  if p_action <> 'status' and (p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$') then
    return jsonb_build_object('code',401,'error','Нужна личная секретная ссылка.');
  end if;
  if p_action in ('create','edit') then
    p_name := btrim(p_name);
    p_size := btrim(p_size);
    if p_name is null or p_size is null or length(p_name) not between 1 and 60
       or length(p_size) not between 1 and 40 or p_name ~ '[[:cntrl:]]' or p_size ~ '[[:cntrl:]]' then
      return jsonb_build_object('code',400,'error','Проверь имя (до 60 символов) и размер (до 40 символов).');
    end if;
  end if;

  select * into strict v_event from trusosanta_private.event where id=1 for update;
  v_now := clock_timestamp(); -- Check AFTER obtaining the lock, never the transaction start time.
  if v_event.status='open' and v_now >= v_event.deadline then
    select array_agg(id order by gen_random_uuid()) into v_ids from trusosanta_private.participants;
    v_count := coalesce(array_length(v_ids,1),0);
    if v_count < 3 then
      v_event.status := 'insufficient';
    else
      for i in 1..v_count loop
        insert into trusosanta_private.assignments(giver,receiver)
        values (v_ids[i],v_ids[(i % v_count)+1]);
      end loop;
      v_event.status := 'drawn';
    end if;
    update trusosanta_private.event set status=v_event.status where id=1;
  end if;
  v_state := jsonb_build_object('status',v_event.status,
    'deadline',floor(extract(epoch from v_event.deadline)*1000)::bigint,
    'serverTime',floor(extract(epoch from v_now)*1000)::bigint);
  if p_action='status' then return v_state; end if;

  select * into v_person from trusosanta_private.participants where key_hash=p_key_hash;
  -- An accepted creation can be retried without changing the record, even after closing.
  if p_action in ('create','edit','delete') and not (p_action='create' and v_person.id is not null) then
    if v_event.status <> 'open' then
      return jsonb_build_object('code',409,'error','Приём заявок завершён. Изменения больше не принимаются.');
    end if;
    if p_action='create' then
      if (select count(*) from trusosanta_private.participants) >= 500 then
        return jsonb_build_object('code',409,'error','Лимит участников достигнут.');
      end if;
      insert into trusosanta_private.participants(key_hash,name,size) values(p_key_hash,p_name,p_size)
        returning * into v_person;
    elsif p_action='edit' then
      if v_person.id is null then return jsonb_build_object('code',404,'error','Заявка по этой ссылке не найдена.'); end if;
      update trusosanta_private.participants set name=p_name,size=p_size where id=v_person.id
        returning * into v_person;
    elsif p_action='delete' then
      delete from trusosanta_private.participants where key_hash=p_key_hash;
      return v_state || jsonb_build_object('entry',null,'recipient',null);
    end if;
  end if;
  if v_person.id is null then return jsonb_build_object('code',404,'error','Заявка по этой ссылке не найдена.'); end if;
  v_result := v_state || jsonb_build_object('entry',jsonb_build_object('name',v_person.name,'size',v_person.size),'recipient',null);
  if v_event.status='drawn' then
    select p.* into strict v_receiver from trusosanta_private.assignments a
      join trusosanta_private.participants p on p.id=a.receiver where a.giver=v_person.id;
    v_result := v_result || jsonb_build_object('recipient',jsonb_build_object('name',v_receiver.name,'size',v_receiver.size));
  end if;
  return v_result;
end;
$$;
revoke all on function public.trusosanta_request(text,text,text,text) from public, anon, authenticated;
grant execute on function public.trusosanta_request(text,text,text,text) to service_role;
