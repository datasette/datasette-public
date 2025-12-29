from datasette.app import Datasette
import pytest
import pytest_asyncio
import sqlite3
from collections import namedtuple


@pytest_asyncio.fixture
async def ds(tmpdir):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    ds = Datasette([db_path], internal=internal_path)
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
    # Set up test environment - use default_deny mode for this test
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
    ds = Datasette(files=[db_path])
    ds.root_enabled = True
    with pytest.raises(ValueError):
        await ds.invoke_startup()


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
    if not public_instance:
        config["allow"] = False

    ds = Datasette([db_path], internal=internal_path, config=config)
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

    ds = Datasette([db_path], internal=internal_path, config={"allow": False})
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
    # This should not
    assert (await ds.client.get("/data")).status_code == 403
    # Neither should this
    response = await ds.client.get("/data/t1?_where=1==1")
    assert ">1 extra where clause<" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("user_is_root", (True, False))
@pytest.mark.parametrize("is_view", (True, False))
async def test_ui_for_editing_table_privacy(tmpdir, user_is_root, is_view):
    # This test uses default_deny mode to test public_tables behavior
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
    # This test uses default_deny mode - tables cannot be toggled if the database they are in is public
    # via some other means (not via the plugin)
    internal_path = str(tmpdir / "internal.db")
    data_path = str(tmpdir / "data.db")
    conn2 = sqlite3.connect(data_path)
    conn2.execute("create table t1 (id int)")
    conn2.close()

    if database_is_private:
        # Database is private - only root can access
        config = {"allow": {"id": "root"}}
    else:
        # Database is public via config (anyone can view)
        config = {
            "databases": {
                "data": {"permissions": {"view-database": True, "view-table": True}}
            }
        }

    ds = Datasette(
        [data_path],
        internal=internal_path,
        config=config,
        default_deny=True,
    )
    ds.root_enabled = True
    await ds.invoke_startup()
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


DatabaseActionsTest = namedtuple(
    "DatabaseActionsTest",
    (
        "description",
        "in_public_databases",
        "instance_allows_all",
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
            instance_allows_all=True,
            should_show=True,
        ),
        DatabaseActionsTest(
            description="Database not in public_databases, with default_deny -> show action (can make public)",
            in_public_databases=False,
            instance_allows_all=True,
            should_show=True,
        ),
    ),
)
async def test_database_actions(
    tmpdir,
    description,
    in_public_databases,
    instance_allows_all,
    should_show,
):
    """
    Test database actions behavior in default_deny mode:
    - Show when database IS in public_databases (can make it private)
    - Show when database is NOT in public_databases (can make it public)
    """
    internal_path = str(tmpdir / "internal.db")
    internal_conn = sqlite3.connect(internal_path)
    data_path = str(tmpdir / "data.db")
    conn2 = sqlite3.connect(data_path)
    conn2.execute("create table t1 (id int)")

    config = {}
    if instance_allows_all:
        # Make instance/databases visible via instance-level permission
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
    ds = Datasette([], internal=internal_path, config={"allow": {"id": "*"}})
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
                    "queries": {"test_query": {"sql": "SELECT 'hello' as greeting"}}
                }
            },
            "permissions": {"datasette-public": {"id": "root"}},
        },
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

    # Make database public
    ds = Datasette(
        [db_path],
        internal=internal_path,
        config={
            "databases": {
                "data": {
                    "queries": {"test_query": {"sql": "SELECT 'hello' as greeting"}}
                }
            }
        },
    )
    ds.root_enabled = True
    await ds.invoke_startup()

    cookies = {"ds_actor": ds.sign({"a": {"id": "root"}}, "actor")}

    # Query actions should not appear when database is public
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
    ds = Datasette([], internal=internal_path)
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

    ds = Datasette([db_path], internal=internal_path, config=config)
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

    ds = Datasette([db_path], internal=internal_path, config=config)
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


# =============================================================================
# default_deny mode tests
# =============================================================================


@pytest.mark.asyncio
async def test_database_privacy_form_shown_without_default_deny(tmpdir):
    """
    Without --default-deny, all databases are visible by default.
    The privacy toggle form SHOULD be shown - can hide databases from anonymous users.
    """
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    conn.close()

    # default_deny=False is the default
    ds = Datasette([db_path], internal=internal_path)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Login as root to access the privacy page
    cookies = {"ds_actor": ds.sign({"a": {"id": "root"}}, "actor")}
    response = await ds.client.get("/-/public-database/data", cookies=cookies)

    assert response.status_code == 200
    # Should show the form to hide from anonymous users
    assert "visible to everyone" in response.text
    assert 'name="action"' in response.text
    assert "Hide from anonymous users" in response.text


@pytest.mark.asyncio
async def test_private_table_still_visible_to_logged_in_user(tmpdir):
    """
    When a table is in private_tables, it should be hidden from anonymous users
    but still visible to logged-in users (the deny only applies to anonymous).

    Regression test for: "You did not supply a value for binding parameter :actor"
    """
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    conn.execute("create table t2 (id int)")
    conn.close()

    ds = Datasette([db_path], internal=internal_path, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Make database public with SQL disabled
    internal_conn = sqlite3.connect(internal_path)
    with internal_conn:
        internal_conn.execute(
            "insert into public_databases (database_name, allow_sql) values (?, ?)",
            ["data", 0],
        )
        # Make t1 private (hidden from anonymous)
        internal_conn.execute(
            "insert into private_tables (database_name, table_name) values (?, ?)",
            ["data", "t1"],
        )

    # Anonymous user should NOT see t1
    anon_response = await ds.client.get("/data/t1")
    assert anon_response.status_code == 403, "Anonymous should not see private table"

    # Anonymous user should see t2
    anon_response2 = await ds.client.get("/data/t2")
    assert anon_response2.status_code == 200, "Anonymous should see public table"

    # Logged-in user should STILL see t1
    cookies = {"ds_actor": ds.sign({"a": {"id": "someuser"}}, "actor")}
    logged_in_response = await ds.client.get("/data/t1", cookies=cookies)
    assert (
        logged_in_response.status_code == 200
    ), "Logged-in user should still see private table"


@pytest.mark.asyncio
async def test_database_privacy_form_shown_with_default_deny(tmpdir):
    """
    With --default-deny, the plugin's grants matter.
    The privacy toggle form should be shown.
    """
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    conn.close()

    # Enable default_deny mode
    ds = Datasette([db_path], internal=internal_path, default_deny=True)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Login as root to access the privacy page
    cookies = {"ds_actor": ds.sign({"a": {"id": "root"}}, "actor")}
    response = await ds.client.get("/-/public-database/data", cookies=cookies)

    assert response.status_code == 200
    # Should show the form, not the "instance is public" message
    assert "instance is currently public" not in response.text
    assert 'name="action"' in response.text


# =============================================================================
# Non-default-deny mode tests (hiding from anonymous)
# =============================================================================

HideFromAnonymousTest = namedtuple(
    "HideFromAnonymousTest",
    ("resource_type", "resource_url", "control_url", "label_fragment"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    HideFromAnonymousTest._fields,
    (
        HideFromAnonymousTest(
            resource_type="database",
            resource_url="/data",
            control_url="/-/public-database/data",
            label_fragment="Hide this database from anonymous users",
        ),
        HideFromAnonymousTest(
            resource_type="table",
            resource_url="/data/t1",
            control_url="/-/public-table/data/t1",
            label_fragment="Hide this table from anonymous users",
        ),
    ),
)
async def test_hide_from_anonymous_without_default_deny(
    tmpdir, resource_type, resource_url, control_url, label_fragment
):
    """
    Without --default-deny, users can hide databases/tables from anonymous users.
    """
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")

    conn = sqlite3.connect(db_path)
    conn.execute("create table t1 (id int)")
    conn.close()

    ds = Datasette([db_path], internal=internal_path)
    ds.root_enabled = True
    await ds.invoke_startup()

    # Anonymous can see resource
    assert (await ds.client.get(resource_url)).status_code == 200

    # Login as root
    cookies = {"ds_actor": ds.sign({"a": {"id": "root"}}, "actor")}

    # Check action menu shows hide option
    response = await ds.client.get(resource_url, cookies=cookies)
    assert response.status_code == 200
    assert label_fragment in response.text

    # Get CSRF token from control page
    control_response = await ds.client.get(control_url, cookies=cookies)
    assert control_response.status_code == 200
    csrf = control_response.cookies["ds_csrftoken"]
    cookies["ds_csrftoken"] = csrf

    # Hide from anonymous
    hide_response = await ds.client.post(
        control_url,
        cookies=cookies,
        data={"action": "make-private", "csrftoken": csrf},
    )
    assert hide_response.status_code == 302

    # Anonymous can no longer see resource
    assert (await ds.client.get(resource_url)).status_code == 403

    # Logged-in user can still see it
    assert (await ds.client.get(resource_url, cookies=cookies)).status_code == 200

    # Make visible again
    show_response = await ds.client.post(
        control_url,
        cookies=cookies,
        data={"action": "make-public", "csrftoken": csrf},
    )
    assert show_response.status_code == 302

    # Anonymous can see it again
    assert (await ds.client.get(resource_url)).status_code == 200
