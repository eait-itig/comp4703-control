CREATE TYPE public.alloc_state AS ENUM (
    'waiting',
    'allocated',
    'busy',
    'closed'
);

CREATE TYPE public.worker_state AS ENUM (
    'provisioning',
    'ready',
    'assigned',
    'busy',
    'destroying'
);

CREATE SEQUENCE public.allocation_id_seq;
CREATE TABLE public.allocations (
    id bigint DEFAULT nextval('public.allocation_id_seq'::regclass) NOT NULL PRIMARY KEY,
    zone_id uuid NOT NULL,
    worker_hostname character varying(256),
    state public.alloc_state DEFAULT 'waiting'::public.alloc_state NOT NULL,
    created timestamp without time zone DEFAULT now() NOT NULL,
    allocated timestamp without time zone,
    first_connect timestamp without time zone,
    closed timestamp without time zone,
    ssh_user_id bigint,
    ssh_host_id bigint,
    ssh_host_group_id bigint,
    ssh_user_group_id bigint,
    ssh_acl_id bigint,
    charged_until timestamp without time zone,
    last_connect timestamp without time zone
);
CREATE INDEX ON public.allocations USING btree (ssh_user_id, ssh_host_id);
CREATE INDEX ON public.allocations USING btree (worker_hostname, state);
CREATE INDEX ON public.allocations USING btree (zone_id, state);

CREATE TABLE public.config (
    key character varying(32) NOT NULL PRIMARY KEY,
    value character varying(2048) NOT NULL
);
INSERT INTO config VALUES ('instance_type', 'g5.xlarge');
INSERT INTO config VALUES ('xusers', 'uqawil16 uqdgwynn');
INSERT INTO config VALUES ('pool_max', '8');
INSERT INTO config VALUES ('pool_spares', '1');
INSERT INTO config VALUES ('pool_idle_mins', '30');
INSERT INTO config VALUES ('charge_increment_mins', '5');

CREATE TABLE public.quotas (
    username character varying(32) NOT NULL,
    quota_mins integer DEFAULT 0,
    used_mins integer DEFAULT 0
);

CREATE TABLE public.workers (
    hostname character varying(256) NOT NULL PRIMARY KEY,
    vpn_addr inet NOT NULL,
    provision_token character varying(32),
    auth_key character varying(1024),
    state public.worker_state DEFAULT 'provisioning'::public.worker_state NOT NULL,
    state_change timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.zones (
    id uuid NOT NULL PRIMARY KEY,
    vpn_addr inet NOT NULL,
    owner character varying(32),
    auth_key character varying(1024) NOT NULL
);

CREATE TABLE public.pool_size_history (
    "time" timestamp without time zone DEFAULT now() NOT NULL PRIMARY KEY,
    total integer NOT NULL,
    spares integer NOT NULL
);

CREATE TABLE public.nfs_servers (
    ip inet NOT NULL PRIMARY KEY,
    hostname character varying(32) NOT NULL,
    auth_key character varying(1024)
);

GRANT USAGE ON SEQUENCE public.allocation_id_seq TO "www-data";
GRANT SELECT,INSERT,UPDATE ON TABLE public.allocations TO "www-data";
GRANT SELECT,INSERT,UPDATE ON TABLE public.quotas TO "www-data";
GRANT SELECT,UPDATE ON TABLE public.workers TO "www-data";
GRANT SELECT ON TABLE public.zones TO "www-data";
GRANT SELECT,UPDATE ON TABLE public.config TO "www-data";
GRANT SELECT ON TABLE public.nfs_servers TO "www-data";
GRANT SELECT ON TABLE public.pool_size_history TO "www-data";
