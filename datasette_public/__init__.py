from datasette import hookimpl, Forbidden, Response, NotFound, Permission
from urllib.parse import quote_plus, unquote_plus
from typing import Tuple

CREATE_TABLES_SQL = """
create table if not exists public_tables (
    database_name text,
    table_name text,
    primary key (database_name, table_name)
);
create table if not exists public_databases (
    database_name text primary key,
    allow_sql integer default 0
);
create table if not exists public_queries (
    database_name text,
    query_name text,
    primary key (database_name, query_name)
);
create table if not exists public_audit_log (
    id integer primary key,
    timestamp text default (datetime('now')),
    operation_by text,
    operation text check (operation in ('make_public', 'make_private', 'sql_enabled', 'sql_disabled')),
    database_name text,
    table_name text,
    query_name text
);
""".strip()


@hookimpl
def startup(datasette):
    async def inner():
        db = datasette.get_internal_database()
        if db.is_memory:
            raise ValueError("datasette-public requires a persistent database")
        await db.execute_write_script(CREATE_TABLES_SQL)
        # Ensure query_name column exists
        try:
            await db.execute_write(
                "alter table public_audit_log add column query_name text"
            )
        except Exception:
            pass

    return inner


@hookimpl
def register_permissions():
    return [
        Permission(
            name="datasette-public",
            abbr=None,
            description="Make tables and databases public/private",
            takes_database=True,
            takes_resource=False,
            default=False,
        ),
    ]


@hookimpl
def permission_allowed(datasette, action, actor, resource):
    async def inner():
        # Root actor can always edit public status
        if actor and actor.get("id") == "root" and action == "datasette-public":
            return True
        if action == "execute-sql" and not actor:
            # We now have an opinion on execute-sql for anonymous users
            _, allow_sql = await database_privacy_settings(datasette, resource)
            return allow_sql
        if action not in ("view-table", "view-database", "view-query"):
            return None
        if action == "view-table" and await table_is_public(
            datasette, resource[0], resource[1]
        ):
            return True
        if action == "view-database":
            is_public, _ = await database_privacy_settings(datasette, resource)
            if is_public:
                return True
        if action == "view-query" and await query_is_public(
            datasette, resource[0], resource[1]
        ):
            return True

    return inner


async def table_is_public(datasette, database_name, table_name):
    db = datasette.get_internal_database()
    rows = await db.execute(
        "select 1 from public_tables where database_name = ? and table_name = ?",
        (database_name, table_name),
    )
    return bool(len(rows))


async def database_privacy_settings(datasette, database_name) -> Tuple[bool, bool]:
    db = datasette.get_internal_database()
    result = await db.execute(
        "select 1, allow_sql from public_databases where database_name = ?",
        [database_name],
    )
    row = result.first()
    if not row:
        return (False, False)
    return (True, bool(row["allow_sql"]))


async def query_is_public(datasette, database_name, query_name):
    db = datasette.get_internal_database()
    rows = await db.execute(
        "select 1 from public_queries where database_name = ? and query_name = ?",
        (database_name, query_name),
    )
    return bool(len(rows))


@hookimpl
def table_actions(datasette, actor, database, table):
    async def inner():
        if not await datasette.permission_allowed(
            actor, "datasette-public", resource=database
        ):
            return
        database_visible, database_private = await datasette.check_visibility(
            actor, permissions=[("view-database", database), "view-instance"]
        )
        if database_visible and not database_private:
            return
        noun = "table"
        if table in await datasette.get_database(database).view_names():
            noun = "view"
        is_private = not await table_is_public(datasette, database, table)
        return [
            {
                "href": datasette.urls.path(
                    "/-/public-table/{}/{}".format(database, quote_plus(table))
                ),
                "label": "Make {} {}".format(
                    noun, "public" if is_private else "private"
                ),
                "description": (
                    "Allow anyone to view this {}".format(noun)
                    if is_private
                    else "Only allow logged-in users to view this {}".format(noun)
                ),
            }
        ]

    return inner


@hookimpl
def database_actions(datasette, actor, database):
    async def inner():
        if not await datasette.permission_allowed(
            actor, "datasette-public", resource=database
        ):
            return
        instance_visible, instance_private = await datasette.check_visibility(
            actor, permissions=["view-instance"]
        )
        if instance_visible and not instance_private:
            return

        is_public, _ = await database_privacy_settings(datasette, database)
        return [
            {
                "href": datasette.urls.path(
                    "/-/public-database/{}".format(quote_plus(database))
                ),
                "label": "Change database visibility",
                "description": (
                    "Only allow logged-in users to view this database"
                    if is_public
                    else "Allow anyone to view this database"
                ),
            }
        ]

    return inner


@hookimpl
def view_actions(datasette, actor, database, view):
    return table_actions(datasette, actor, database, view)


@hookimpl
def query_actions(datasette, actor, database, query_name):
    async def inner():
        if not await datasette.permission_allowed(
            actor, "datasette-public", resource=database
        ):
            return
        database_visible, database_private = await datasette.check_visibility(
            actor, permissions=[("view-database", database), "view-instance"]
        )
        if (not database_visible) or database_private:
            return
        is_private = not await query_is_public(datasette, database, query_name)
        return [
            {
                "href": datasette.urls.path(
                    "/-/public-query/{}/{}".format(database, quote_plus(query_name))
                ),
                "label": "Make query {}".format("public" if is_private else "private"),
                "description": (
                    "Allow anyone to view this query"
                    if is_private
                    else "Only allow logged-in users to view this query"
                ),
            }
        ]

    return inner


async def check_permissions(datasette, request, database):
    if not await datasette.permission_allowed(
        request.actor, "datasette-public", resource=database
    ):
        raise Forbidden("Permission denied for changing table privacy")


async def add_audit_log(
    db, actor_id, operation, database_name, table_name=None, query_name=None
):
    sql = f"""
        insert into public_audit_log (
            operation_by, operation, database_name, table_name, query_name
        ) values (
            :actor_id, :operation, :database_name,
            {':table_name' if table_name else 'null'},
            {':query_name' if query_name else 'null'}
        )"""
    params = {
        "actor_id": actor_id,
        "operation": operation,
        "database_name": database_name,
        "table_name": table_name,
        "query_name": query_name,
    }
    await db.execute_write(sql, params)


async def change_table_privacy(request, datasette):
    table = unquote_plus(request.url_vars["table"])
    database_name = request.url_vars["database"]
    await check_permissions(datasette, request, database_name)
    this_db = datasette.get_database(database_name)
    is_view = table in await this_db.view_names()
    noun = "View" if is_view else "Table"
    if (
        not await this_db.table_exists(table)
        # This can use db.view_exists() after that goes out in a stable release
        and table not in await this_db.view_names()
    ):
        raise NotFound("{} not found".format(noun))

    permission_db = datasette.get_internal_database()
    next_id = request.args.get("next", None)
    limit = 10

    where = ["database_name = :database and table_name = :table"]
    params = {"database": database_name, "table": table}
    if next_id:
        where.append("id < :next_id")
        params["next_id"] = next_id

    audit_log = (
        await permission_db.execute(
            f"""
        select *, id as next_page
        from public_audit_log
        where {" and ".join(where)}
        order by id desc
        limit {limit + 1}
        """,
            params,
        )
    ).rows

    next_page = None
    if len(audit_log) > limit:
        next_page = audit_log[limit - 1]["next_page"]
        audit_log = audit_log[:limit]

    if request.method == "POST":
        form_data = await request.post_vars()
        action = form_data.get("action")
        was_public = await table_is_public(datasette, database_name, table)
        msg_type = datasette.INFO
        if action == "make-public":
            if not was_public:
                await permission_db.execute_write(
                    "insert or ignore into public_tables (database_name, table_name) values (?, ?)",
                    [database_name, table],
                )
                await add_audit_log(
                    permission_db,
                    request.actor.get("id"),
                    "make_public",
                    database_name,
                    table,
                )
                msg = "now public"
            else:
                msg = "already public"
                msg_type = datasette.WARNING
        elif action == "make-private":
            if was_public:
                await permission_db.execute_write(
                    "delete from public_tables where database_name = ? and table_name = ?",
                    [database_name, table],
                )
                await add_audit_log(
                    permission_db,
                    request.actor.get("id"),
                    "make_private",
                    database_name,
                    table,
                )
                msg = "now private"
            else:
                msg = "already private"
                msg_type = datasette.WARNING
        datasette.add_message(
            request, "{} '{}' is {}".format(noun, table, msg), msg_type
        )
        return Response.redirect(datasette.urls.table(database_name, table))

    is_private = not await table_is_public(datasette, database_name, table)

    database_visible, database_private = await datasette.check_visibility(
        request.actor, permissions=[("view-database", database_name), "view-instance"]
    )
    database_is_public = database_visible and not database_private

    return Response.html(
        await datasette.render_template(
            "public_table_change_privacy.html",
            {
                "database": database_name,
                "table": table,
                "is_private": is_private,
                "noun": noun.lower(),
                "database_is_public": database_is_public,
                "audit_log": audit_log,
                "next_page": next_page,
            },
            request=request,
        )
    )


async def change_database_privacy(request, datasette):
    database_name = request.url_vars["database"]
    await check_permissions(datasette, request, database_name)
    permission_db = datasette.get_internal_database()

    if request.method == "POST":
        form_data = await request.post_vars()
        allow_sql = bool(form_data.get("allow_sql"))
        action = form_data.get("action")
        current_settings = await database_privacy_settings(datasette, database_name)
        was_public, had_sql = current_settings
        msg_type = datasette.INFO
        msg = None

        if action == "make-public":
            settings_changed = False
            if not was_public:
                settings_changed = True
                await permission_db.execute_write(
                    "insert or replace into public_databases (database_name, allow_sql) values (?, ?)",
                    (database_name, allow_sql),
                )
                await add_audit_log(
                    permission_db, request.actor.get("id"), "make_public", database_name
                )
                if allow_sql:
                    await add_audit_log(
                        permission_db,
                        request.actor.get("id"),
                        "sql_enabled",
                        database_name,
                    )
                msg = "now public"
            else:
                # Already public, but SQL setting might have changed
                if allow_sql != had_sql:
                    await permission_db.execute_write(
                        "update public_databases set allow_sql = ? where database_name = ?",
                        (allow_sql, database_name),
                    )
                    await add_audit_log(
                        permission_db,
                        request.actor.get("id"),
                        "sql_enabled" if allow_sql else "sql_disabled",
                        database_name,
                    )
                    msg = "public (execute SQL is now {})".format(
                        "enabled" if allow_sql else "disabled"
                    )
                else:
                    msg = "already public"
                    msg_type = datasette.WARNING
        elif action == "make-private":
            if was_public:
                if had_sql:
                    await add_audit_log(
                        permission_db,
                        request.actor.get("id"),
                        "sql_disabled",
                        database_name,
                    )
                await permission_db.execute_write(
                    "delete from public_databases where database_name = ?",
                    [database_name],
                )
                await add_audit_log(
                    permission_db,
                    request.actor.get("id"),
                    "make_private",
                    database_name,
                )
                msg = "now private"
            else:
                msg = "already private"
                msg_type = datasette.WARNING

        datasette.add_message(
            request, "Database '{}' is {}".format(database_name, msg), msg_type
        )
        return Response.redirect(datasette.urls.database(database_name))

    is_public, allow_sql = await database_privacy_settings(datasette, database_name)

    instance_visible, instance_private = await datasette.check_visibility(
        request.actor, permissions=["view-instance"]
    )
    instance_is_public = instance_visible and not instance_private

    next_id = request.args.get("next", None)
    limit = 10

    where = ["database_name = :database"]
    params = {"database": database_name}
    if next_id:
        where.append("id < :next_id")
        params["next_id"] = next_id

    audit_log = (
        await permission_db.execute(
            f"""
        select *, id as next_page
        from public_audit_log
        where {" and ".join(where)}
        order by id desc
        limit {limit + 1}
        """,
            params,
        )
    ).rows

    next_page = None
    if len(audit_log) > limit:
        next_page = audit_log[limit - 1]["next_page"]
        audit_log = audit_log[:limit]

    return Response.html(
        await datasette.render_template(
            "public_database_change_privacy.html",
            {
                "database": database_name,
                "is_private": not is_public,
                "allow_sql": allow_sql,
                "instance_is_public": instance_is_public,
                "audit_log": audit_log,
                "next_page": next_page,
            },
            request=request,
        )
    )


async def change_query_privacy(request, datasette):
    query = unquote_plus(request.url_vars["query"])
    database_name = request.url_vars["database"]
    await check_permissions(datasette, request, database_name)

    permission_db = datasette.get_internal_database()
    next_id = request.args.get("next", None)
    limit = 10

    where = ["database_name = :database and query_name = :query"]
    params = {"database": database_name, "query": query}
    if next_id:
        where.append("id < :next_id")
        params["next_id"] = next_id

    audit_log = (
        await permission_db.execute(
            f"""
        select *, id as next_page
        from public_audit_log
        where {" and ".join(where)}
        order by id desc
        limit {limit + 1}
        """,
            params,
        )
    ).rows

    next_page = None
    if len(audit_log) > limit:
        next_page = audit_log[limit - 1]["next_page"]
        audit_log = audit_log[:limit]

    if request.method == "POST":
        form_data = await request.post_vars()
        action = form_data.get("action")
        was_public = await query_is_public(datasette, database_name, query)
        msg_type = datasette.INFO
        if action == "make-public":
            if not was_public:
                await permission_db.execute_write(
                    "insert or ignore into public_queries (database_name, query_name) values (?, ?)",
                    [database_name, query],
                )
                await add_audit_log(
                    permission_db,
                    request.actor.get("id"),
                    "make_public",
                    database_name,
                    query_name=query,
                )
                msg = "now public"
            else:
                msg = "already public"
                msg_type = datasette.WARNING
        elif action == "make-private":
            if was_public:
                await permission_db.execute_write(
                    "delete from public_queries where database_name = ? and query_name = ?",
                    [database_name, query],
                )
                await add_audit_log(
                    permission_db,
                    request.actor.get("id"),
                    "make_private",
                    database_name,
                    query_name=query,
                )
                msg = "now private"
            else:
                msg = "already private"
                msg_type = datasette.WARNING
        datasette.add_message(request, "Query '{}' is {}".format(query, msg), msg_type)
        return Response.redirect(datasette.urls.query(database_name, query))

    is_private = not await query_is_public(datasette, database_name, query)

    database_visible, database_private = await datasette.check_visibility(
        request.actor, permissions=[("view-database", database_name), "view-instance"]
    )
    database_is_public = database_visible and not database_private

    return Response.html(
        await datasette.render_template(
            "public_query_change_privacy.html",
            {
                "database": database_name,
                "query": query,
                "is_private": is_private,
                "database_is_public": database_is_public,
                "audit_log": audit_log,
                "next_page": next_page,
            },
            request=request,
        )
    )


@hookimpl
def register_routes():
    return [
        (
            r"^/-/public-table/(?P<database>[^/]+)/(?P<table>[^/]+)$",
            change_table_privacy,
        ),
        (
            r"^/-/public-database/(?P<database>[^/]+)$",
            change_database_privacy,
        ),
        (
            r"^/-/public-query/(?P<database>[^/]+)/(?P<query>[^/]+)$",
            change_query_privacy,
        ),
    ]
