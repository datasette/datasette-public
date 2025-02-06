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
""".strip()


@hookimpl
def startup(datasette):
    async def inner():
        db = datasette.get_internal_database()
        if db.is_memory:
            raise ValueError("datasette-public requires a persistent database")
        await db.execute_write_script(CREATE_TABLES_SQL)

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
        if action not in ("view-table", "view-database"):
            return None
        if action == "view-table" and await table_is_public(
            datasette, resource[0], resource[1]
        ):
            return True
        if action == "view-database":
            is_public, _ = await database_privacy_settings(datasette, resource)
            if is_public:
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
                "label": "Make database {}".format(
                    "private" if is_public else "public"
                ),
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


async def check_permissions(datasette, request, database):
    if not await datasette.permission_allowed(
        request.actor, "datasette-public", resource=database
    ):
        raise Forbidden("Permission denied for changing table privacy")


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

    if request.method == "POST":
        form_data = await request.post_vars()
        action = form_data.get("action")
        if action == "make-public":
            msg = "public"
            await permission_db.execute_write(
                "insert or ignore into public_tables (database_name, table_name) values (?, ?)",
                [database_name, table],
            )
        elif action == "make-private":
            msg = "private"
            await permission_db.execute_write(
                "delete from public_tables where database_name = ? and table_name = ?",
                [database_name, table],
            )
        datasette.add_message(request, "{} '{}' is now {}".format(noun, table, msg))
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
        if action == "make-public":
            msg = "public"
            await permission_db.execute_write(
                "insert or replace into public_databases (database_name, allow_sql) values (?, ?)",
                (database_name, allow_sql),
            )
        elif action == "make-private":
            msg = "private"
            await permission_db.execute_write(
                "delete from public_databases where database_name = ?", [database_name]
            )
        datasette.add_message(
            request, "Database '{}' is now {}".format(database_name, msg)
        )
        return Response.redirect(datasette.urls.database(database_name))

    is_public, allow_sql = await database_privacy_settings(datasette, database_name)

    instance_visible, instance_private = await datasette.check_visibility(
        request.actor, permissions=["view-instance"]
    )
    instance_is_public = instance_visible and not instance_private

    return Response.html(
        await datasette.render_template(
            "public_database_change_privacy.html",
            {
                "database": database_name,
                "is_private": not is_public,
                "allow_sql": allow_sql,
                "instance_is_public": instance_is_public,
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
    ]
