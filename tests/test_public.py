from datasette.app import Datasette
import pytest
import pytest_asyncio
import sqlite3
from collections import namedtuple


@pytest_asyncio.fixture
async def ds(tmpdir):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    ds = Datasette([db_path], internal=internal_path, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()
    return ds


@pytest.mark.asyncio
async def test_plugin_creates_table(ds):
    db = ds.get_internal_database()
    table_names = await db.table_names()
    assert "public_tables" in table_names
    assert "public_databases" in table_names
    assert "public_audit_log" in table_names


@pytest.mark.asyncio
async def test_audit_logs(tmpdir):
    # Set up test environment
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    ds = Datasette(
        [db_path],
        internal=internal_path,
        config={"allow": {"id": "*"}},
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()
    cookies = {"ds_actor": ds.sign({"a": {"id": "root"}}, "actor")}
    csrf = None

    # Helper to get CSRF and make requests
    async def post_action(path, action, allow_sql=None):
        nonlocal csrf

        response = await ds.client.get(path, cookies=cookies)
        if "ds_csrftoken" in response.cookies:
            csrf = response.cookies["ds_csrftoken"]
            cookies["ds_csrftoken"] = csrf
        data = {"action": action, "csrftoken": csrf}
        if allow_sql is not None:
            data["allow_sql"] = allow_sql
        return await ds.client.post(path, cookies=cookies, data=data)

    # Test table privacy changes
    await post_action("/-/public-table/data/t1", "make-public")
    await post_action("/-/public-table/data/t1", "make-public")  # Redundant
    await post_action("/-/public-table/data/t1", "make-private")
    await post_action("/-/public-table/data/t1", "make-private")  # Redundant

    # Test database privacy changes
    await post_action("/-/public-database/data", "make-public", allow_sql=True)
    await post_action(
        "/-/public-database/data", "make-public", allow_sql=True
    )  # Redundant
    await post_action("/-/public-database/data", "make-public", allow_sql=False)
    await post_action("/-/public-database/data", "make-private")
    await post_action("/-/public-database/data", "make-private")  # Redundant

    # Each tuple is (actor_id, operation, database_name, table_name)
    expected_operations = [
        ("root", "make_public", "data", "t1"),  # Make table public
        ("root", "make_private", "data", "t1"),  # Make table private
        ("root", "make_public", "data", None),  # Make database public
        ("root", "sql_enabled", "data", None),  # With SQL enabled
        ("root", "sql_disabled", "data", None),  # Toggle SQL off
        ("root", "make_private", "data", None),  # Make database private
    ]

    logs = _get_audit_logs(internal_path)
    assert logs == expected_operations


@pytest.mark.asyncio
async def test_error_if_no_internal_database(tmpdir):
    db_path = str(tmpdir / "data.db")
    ds = Datasette(files=[db_path], default_deny=True)
    ds.root_enabled = True
    with pytest.raises(ValueError) as exc_info:
        await ds.invoke_startup()
    assert "persistent internal database" in str(exc_info.value)


@pytest.mark.asyncio
async def test_error_if_not_default_deny(tmpdir):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    ds = Datasette([db_path], internal=internal_path, default_deny=False)
    ds.root_enabled = True
    with pytest.raises(ValueError) as exc_info:
        await ds.invoke_startup()
    assert "--default-deny" in str(exc_info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "public_instance,public_table,should_allow",
    (
        (True, False, True),
        (False, False, False),
        (False, True, True),
        (True, True, True),
    ),
)
@pytest.mark.parametrize("is_view", (True, False))
async def test_public_table(
    tmpdir, public_instance, public_table, should_allow, is_view
):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    conn = sqlite3.connect(db_path)
    internal_conn = sqlite3.connect(internal_path)

    config = {}
    if public_instance:
        config["allow"] = True

    ds = Datasette([db_path], internal=internal_path, config=config, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()

    if is_view:
        conn.execute("create view t1 as select 1")
    else:
        conn.execute("create table t1 (id int)")
    if public_table:
        with internal_conn:
            internal_conn.execute(
                "insert into public_tables (database_name, table_name) values (?, ?)",
                ["data", "t1"],
            )

    response = await ds.client.get("/data/t1")
    if should_allow:
        assert response.status_code == 200
    else:
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_where_is_denied(tmpdir):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    conn = sqlite3.connect(db_path)
    internal_conn = sqlite3.connect(internal_path)

    ds = Datasette(
        [db_path], internal=internal_path, config={"allow": False}, default_deny=True
    )
    ds.root_enabled = True
    await ds.invoke_startup()

    conn.execute("create table t1 (id int)")
    with internal_conn:
        internal_conn.execute(
            "insert into public_tables (database_name, table_name) values (? ,?)",
            ["data", "t1"],
        )
    # This should be allowed
    assert (await ds.client.get("/data/t1")).status_code == 200
    # This should not be allowed
    assert (await ds.client.get("/data")).status_code == 403
    # Neither should this
    response = await ds.client.get("/data/t1?_where=1==1")
    assert ">1 extra where clause<" not in response.text


@pytest.mark.asyncio
async def test_tables_in_public_database_are_accessible(tmpdir):
    """When a database is made public, all tables within it should be accessible"""
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    conn.execute("create table t2 (name text)")
    internal_conn = sqlite3.connect(internal_path)

    ds = Datasette([db_path], internal=internal_path, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Make database public (but not individual tables)
    with internal_conn:
        internal_conn.execute(
            "insert into public_databases (database_name) values (?)",
            ["data"],
        )

    # Anonymous user should be able to see the database
    assert (await ds.client.get("/data")).status_code == 200
    # And all tables within it
    assert (await ds.client.get("/data/t1")).status_code == 200
    assert (await ds.client.get("/data/t2")).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("user_is_root", (True, False))
@pytest.mark.parametrize("is_view", (True, False))
async def test_ui_for_editing_table_privacy(tmpdir, user_is_root, is_view):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    conn = sqlite3.connect(db_path)
    noun = "table"
    if is_view:
        noun = "view"
        conn.execute("create view t1 as select 1")
    else:
        conn.execute("create table t1 (id int)")
    ds = Datasette(
        [db_path],
        internal=internal_path,
        config={"allow": {"id": "*"}},
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()
    # Regular user can see table but not edit privacy
    cookies = {
        "ds_actor": ds.sign({"a": {"id": "root" if user_is_root else "user"}}, "actor")
    }
    menu_fragment = '<li><a href="/-/public-table/data/t1">Make {} public'.format(noun)
    response = await ds.client.get("/data/t1", cookies=cookies)
    if user_is_root:
        assert menu_fragment in response.text
    else:
        assert menu_fragment not in response.text

    # Check permissions on /-/public-table/data/t1 page
    response2 = await ds.client.get("/-/public-table/data/t1", cookies=cookies)
    if user_is_root:
        assert response2.status_code == 200
    else:
        assert response2.status_code == 403
    # non-root user test ends here
    if not user_is_root:
        return
    # Test root user can toggle table privacy
    html = response2.text
    assert "{} is currently <strong>private</strong>".format(noun.title()) in html
    assert '<input type="hidden" name="action" value="make-public">' in html
    assert '<input type="submit" value="Make public">' in html
    assert _get_public_tables(internal_path) == []
    csrftoken = response2.cookies["ds_csrftoken"]
    cookies["ds_csrftoken"] = csrftoken
    response3 = await ds.client.post(
        "/-/public-table/data/t1",
        cookies=cookies,
        data={"action": "make-public", "csrftoken": csrftoken},
    )
    assert response3.status_code == 302
    assert response3.headers["location"] == "/data/t1"
    assert _get_public_tables(internal_path) == ["t1"]
    logs = _get_audit_logs(internal_path)
    assert len(logs) == 1
    assert logs[0] == ("root", "make_public", "data", "t1")

    # And toggle it private again
    response4 = await ds.client.get("/-/public-table/data/t1", cookies=cookies)
    html2 = response4.text
    assert "{} is currently <strong>public</strong>".format(noun.title()) in html2
    assert '<input type="hidden" name="action" value="make-private">' in html2
    assert '<input type="submit" value="Make private">' in html2
    response5 = await ds.client.post(
        "/-/public-table/data/t1",
        cookies=cookies,
        data={"action": "make-private", "csrftoken": csrftoken},
    )
    assert response5.status_code == 302
    assert response5.headers["location"] == "/data/t1"
    assert _get_public_tables(internal_path) == []
    logs = _get_audit_logs(internal_path)
    assert len(logs) == 2
    assert logs[0] == ("root", "make_public", "data", "t1")
    assert logs[1] == ("root", "make_private", "data", "t1")


def _get_public_tables(db_path):
    conn = sqlite3.connect(db_path)
    return [row[0] for row in conn.execute("select table_name from public_tables")]


def _get_audit_logs(db_path):
    conn = sqlite3.connect(db_path)
    return list(
        conn.execute(
            "select operation_by, operation, database_name, table_name from public_audit_log order by id"
        ).fetchall()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "database_is_private,should_show_table_actions",
    (
        (True, True),
        (False, False),
    ),
)
async def test_table_actions(tmpdir, database_is_private, should_show_table_actions):
    # Tables cannot be toggled if the database they are in is public
    internal_path = str(tmpdir / "internal.db")
    internal_conn = sqlite3.connect(internal_path)
    data_path = str(tmpdir / "data.db")
    conn2 = sqlite3.connect(data_path)
    conn2.execute("create table t1 (id int)")
    # Always restrict access to root user only via config
    config = {"allow": {"id": "root"}}
    ds = Datasette(
        [data_path],
        internal=internal_path,
        config=config,
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()
    # If database is NOT private, make it public via the plugin's public_databases table
    if not database_is_private:
        with internal_conn:
            internal_conn.execute(
                "insert into public_databases (database_name) values (?)",
                ["data"],
            )
    cookies = {"ds_actor": ds.client.actor_cookie({"id": "root"})}
    response = await ds.client.get("/data/t1", cookies=cookies)
    fragment = 'a href="/-/public-table/data/t1">Make table public'
    if should_show_table_actions:
        assert fragment in response.text
    else:
        assert fragment not in response.text

    # And fetch the control page
    response2 = await ds.client.get(
        "/-/public-table/data/t1",
        cookies=cookies,
    )
    fragment2 = "cannot change the visibility"
    if should_show_table_actions:
        assert fragment2 not in response2.text
    else:
        assert fragment2 in response2.text
        # Should explain that tables are automatically public when database is public
        assert "all tables within it are automatically public" in response2.text


DatabaseActionsTest = namedtuple(
    "DatabaseActionsTest",
    (
        "description",
        "in_public_databases",
        "visible_to_anon_via_config",
        "should_show",
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    DatabaseActionsTest._fields,
    (
        DatabaseActionsTest(
            description="Database in public_databases -> show action (can make private)",
            in_public_databases=True,
            visible_to_anon_via_config=False,
            should_show=True,
        ),
        DatabaseActionsTest(
            description="Database not in public_databases, not visible to anon -> show action (can make public)",
            in_public_databases=False,
            visible_to_anon_via_config=False,
            should_show=True,
        ),
        DatabaseActionsTest(
            description="Database visible to anon via config -> don't show (toggle wouldn't do anything)",
            in_public_databases=False,
            visible_to_anon_via_config=True,
            should_show=False,
        ),
    ),
)
async def test_database_actions(
    tmpdir,
    description,
    in_public_databases,
    visible_to_anon_via_config,
    should_show,
):
    """
    Test database actions behavior:
    - Show when database IS in public_databases (can make it private)
    - Show when database is NOT in public_databases and NOT visible to anon (can make it public)
    - Don't show when database is visible to anonymous via config (toggle wouldn't help)
    """
    internal_path = str(tmpdir / "internal.db")
    internal_conn = sqlite3.connect(internal_path)
    data_path = str(tmpdir / "data.db")
    conn2 = sqlite3.connect(data_path)
    conn2.execute("create table t1 (id int)")

    config = {}
    if visible_to_anon_via_config:
        # Make database visible to everyone including anonymous
        config["allow"] = True
    else:
        # Only allow root user
        config["allow"] = {"id": "root"}

    ds = Datasette(
        [data_path],
        internal=internal_path,
        config=config,
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()

    # Add database to public_databases if needed
    if in_public_databases:
        with internal_conn:
            internal_conn.execute(
                "insert into public_databases (database_name) values (?)",
                ["data"],
            )

    cookies = {"ds_actor": ds.client.actor_cookie({"id": "root"})}
    response = await ds.client.get("/data", cookies=cookies)
    fragment = 'a href="/-/public-database/data">Change database visibility'

    if should_show:
        assert fragment in response.text
    else:
        assert fragment not in response.text


@pytest.mark.asyncio
async def test_plugin_creates_query_table(ds):
    db = ds.get_internal_database()
    table_names = await db.table_names()
    assert "public_queries" in table_names


@pytest.mark.asyncio
async def test_query_permission_check(tmpdir):
    """Test core query permission functionality without UI"""
    from datasette_public import query_is_public

    internal_path = str(tmpdir / "internal.db")
    ds = Datasette(
        [], internal=internal_path, config={"allow": {"id": "*"}}, default_deny=True
    )
    ds.root_enabled = True
    await ds.invoke_startup()

    # Test query_is_public function
    assert not await query_is_public(ds, "test_db", "test_query")

    # Make query public
    internal_db = ds.get_internal_database()
    await internal_db.execute_write(
        "insert into public_queries (database_name, query_name) values (?, ?)",
        ["test_db", "test_query"],
    )

    # Test query is now public
    assert await query_is_public(ds, "test_db", "test_query")


@pytest.mark.asyncio
@pytest.mark.parametrize("user_is_root", (True, False))
@pytest.mark.parametrize(
    "path,should_have_option",
    (("/data/test_query", True), ("/data/-/query?sql=select+1", False)),
)
async def test_query_actions_ui(tmpdir, user_is_root, path, should_have_option):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    # Create the database file
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE dummy (id INTEGER)")
    conn.close()

    ds = Datasette(
        [db_path],
        internal=internal_path,
        config={
            "allow": {"id": "*"},
            "databases": {
                "data": {
                    "queries": {"test_query": {"sql": "SELECT 'hello' as greeting"}},
                    "permissions": {"execute-sql": True},
                }
            },
            "permissions": {"datasette-public": {"id": "root"}},
        },
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()

    cookies = {
        "ds_actor": ds.sign({"a": {"id": "root" if user_is_root else "user"}}, "actor")
    }

    # Test query page shows action menu for root user only
    response = await ds.client.get(path, cookies=cookies)
    assert response.status_code == 200
    menu_fragment = 'a href="/-/public-query/data/test_query">Make query public'

    if user_is_root and should_have_option:
        assert menu_fragment in response.text
    else:
        assert menu_fragment not in response.text


@pytest.mark.asyncio
async def test_query_privacy_toggle(tmpdir):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    # Create the database file
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE dummy (id INTEGER)")
    conn.close()

    ds = Datasette(
        [db_path],
        internal=internal_path,
        config={
            "databases": {
                "data": {
                    "queries": {"test_query": {"sql": "SELECT 'hello' as greeting"}}
                }
            },
            "allow": {"id": "*"},
        },
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()

    cookies = {"ds_actor": ds.sign({"a": {"id": "root"}}, "actor")}

    # Get privacy control page
    response = await ds.client.get("/-/public-query/data/test_query", cookies=cookies)
    assert response.status_code == 200
    assert "Query is currently <strong>private</strong>" in response.text

    # Make query public
    csrftoken = response.cookies["ds_csrftoken"]
    cookies["ds_csrftoken"] = csrftoken

    response = await ds.client.post(
        "/-/public-query/data/test_query",
        cookies=cookies,
        data={"action": "make-public", "csrftoken": csrftoken},
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/data/test_query"

    # Verify query is now public in database
    assert _get_public_queries(internal_path) == ["test_query"]

    # Verify audit log
    logs = _get_query_audit_logs(internal_path)
    assert len(logs) == 1
    assert logs[0] == ("root", "make_public", "data", "test_query")

    # Toggle back to private
    response = await ds.client.get("/-/public-query/data/test_query", cookies=cookies)
    assert "Query is currently <strong>public</strong>" in response.text

    response = await ds.client.post(
        "/-/public-query/data/test_query",
        cookies=cookies,
        data={"action": "make-private", "csrftoken": csrftoken},
    )
    assert response.status_code == 302

    # Verify query is now private
    assert _get_public_queries(internal_path) == []
    logs = _get_query_audit_logs(internal_path)
    assert len(logs) == 2
    assert logs[1] == ("root", "make_private", "data", "test_query")


@pytest.mark.asyncio
async def test_query_privacy_with_database_privacy(tmpdir):
    """Test that database privacy affects query action visibility"""
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    # Create the database file
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE dummy (id INTEGER)")
    conn.close()

    # Make database public via config (not via the plugin)
    ds = Datasette(
        [db_path],
        internal=internal_path,
        config={
            "databases": {
                "data": {
                    "allow": True,
                    "queries": {"test_query": {"sql": "SELECT 'hello' as greeting"}},
                }
            }
        },
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()

    cookies = {"ds_actor": ds.sign({"a": {"id": "root"}}, "actor")}

    # Query actions should not appear when database is public via config
    response = await ds.client.get("/data/test_query", cookies=cookies)
    menu_fragment = 'a href="/-/public-query/data/test_query">Make query'
    assert menu_fragment not in response.text

    # Privacy control page should show warning
    response = await ds.client.get("/-/public-query/data/test_query", cookies=cookies)
    assert "cannot change the visibility of this query" in response.text


def _get_public_queries(db_path):
    conn = sqlite3.connect(db_path)
    return [row[0] for row in conn.execute("select query_name from public_queries")]


def _get_query_audit_logs(db_path):
    conn = sqlite3.connect(db_path)
    return list(
        conn.execute(
            "select operation_by, operation, database_name, query_name from public_audit_log where query_name is not null order by id"
        ).fetchall()
    )


@pytest.mark.asyncio
async def test_startup_upgrades_audit_log_schema(tmpdir):
    """
    Create an internal.db that is missing the `query_name` column on
    public_audit_log, start Datasette and confirm the column is added.
    """
    internal_path = str(tmpdir / "internal.db")

    # Create a pre-existing internal DB without the query_name column
    conn = sqlite3.connect(internal_path)
    conn.executescript(
        """
        create table public_tables (
            database_name text,
            table_name text,
            primary key (database_name, table_name)
        );
        create table public_databases (
            database_name text primary key,
            allow_sql integer default 0
        );
        create table public_queries (
            database_name text,
            query_name text,
            primary key (database_name, query_name)
        );
        -- Missing query_name here on purpose
        create table public_audit_log (
            id integer primary key,
            timestamp text,
            operation_by text,
            operation text,
            database_name text,
            table_name text
        );
        """
    )
    conn.close()

    # Start Datasette pointing at that internal DB
    ds = Datasette([], internal=internal_path, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Confirm query_name column was added by startup hook
    db = ds.get_internal_database()
    pragma = await db.execute("pragma table_info(public_audit_log)")
    column_names = [row["name"] for row in pragma]
    assert "query_name" in column_names


ExecuteSqlTest = namedtuple(
    "ExecuteSqlTest",
    (
        "description",
        "allow_sql",
        "user_id",
        "expected_status",
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ExecuteSqlTest._fields,
    (
        # allow_sql=True grants SQL to everyone (anonymous and logged-in)
        # This is the key bug fix - previously only anonymous users got access
        ExecuteSqlTest(
            description="allow_sql=True grants to anonymous",
            allow_sql=True,
            user_id=None,
            expected_status=200,
        ),
        ExecuteSqlTest(
            description="allow_sql=True grants to logged-in user",
            allow_sql=True,
            user_id="someuser",
            expected_status=200,
        ),
        # allow_sql=False means plugin doesn't grant SQL
        ExecuteSqlTest(
            description="allow_sql=False, anonymous -> denied",
            allow_sql=False,
            user_id=None,
            expected_status=403,
        ),
        ExecuteSqlTest(
            description="allow_sql=False, logged-in -> denied",
            allow_sql=False,
            user_id="someuser",
            expected_status=403,
        ),
    ),
)
async def test_execute_sql_permission(
    tmpdir,
    description,
    allow_sql,
    user_id,
    expected_status,
):
    """
    Test that execute-sql permission works correctly:
    - allow_sql=True grants SQL to everyone (anonymous and logged-in)
    - allow_sql=False means the plugin doesn't grant SQL access
    """
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    conn.close()

    # Deny execute-sql by default so we can test the plugin's grants
    config = {
        "databases": {"data": {"allow": True}},
        "permissions": {"execute-sql": False},
    }

    ds = Datasette([db_path], internal=internal_path, config=config, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Make database public with specified allow_sql setting
    internal_conn = sqlite3.connect(internal_path)
    with internal_conn:
        internal_conn.execute(
            "insert into public_databases (database_name, allow_sql) values (?, ?)",
            ["data", 1 if allow_sql else 0],
        )

    cookies = {}
    if user_id:
        cookies = {"ds_actor": ds.sign({"a": {"id": user_id}}, "actor")}

    response = await ds.client.get("/data/-/query?sql=select+1", cookies=cookies)
    assert response.status_code == expected_status, f"Failed: {description}"


@pytest.mark.asyncio
async def test_allow_sql_false_does_not_block_other_config_grants(tmpdir):
    """
    Verify that allow_sql=False is neutral (doesn't actively deny),
    so other config rules can still grant SQL access.
    """
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    conn.close()

    # Config grants execute-sql on this database
    config = {
        "databases": {
            "data": {
                "allow": True,
                "permissions": {"execute-sql": True},
            }
        },
    }

    ds = Datasette([db_path], internal=internal_path, config=config, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Make database public with SQL DISABLED via plugin
    internal_conn = sqlite3.connect(internal_path)
    with internal_conn:
        internal_conn.execute(
            "insert into public_databases (database_name, allow_sql) values (?, ?)",
            ["data", 0],
        )

    # User SHOULD still be able to execute SQL (config grant takes effect)
    cookies = {"ds_actor": ds.sign({"a": {"id": "someone"}}, "actor")}
    response = await ds.client.get("/data/-/query?sql=select+1", cookies=cookies)
    assert response.status_code == 200, "Config grant should still allow SQL"
