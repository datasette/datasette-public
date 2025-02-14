from datasette.app import Datasette
import pytest
import pytest_asyncio
import sqlite3


@pytest_asyncio.fixture
async def ds(tmpdir):
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    ds = Datasette([db_path], internal=internal_path)
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
    ds = Datasette([db_path], internal=internal_path, metadata={"allow": {"id": "*"}})
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
    db_path = str(tmpdir / "data.db")
    internal_path = str(tmpdir / "internal.db")
    conn = sqlite3.connect(db_path)
    noun = "table"
    if is_view:
        noun = "view"
        conn.execute("create view t1 as select 1")
    else:
        conn.execute("create table t1 (id int)")
    ds = Datasette([db_path], internal=internal_path, metadata={"allow": {"id": "*"}})
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
    data_path = str(tmpdir / "data.db")
    conn2 = sqlite3.connect(data_path)
    conn2.execute("create table t1 (id int)")
    ds = Datasette(
        [data_path],
        internal=internal_path,
        config=database_is_private and {"allow": {"id": "root"} or {}},
    )
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "instance_is_public,should_show_database_actions",
    (
        (True, True),
        (False, False),
    ),
)
async def test_database_actions(
    tmpdir, instance_is_public, should_show_database_actions
):
    # Database cannot be toggled if the instance they are in is public
    internal_path = str(tmpdir / "internal.db")
    data_path = str(tmpdir / "data.db")
    conn2 = sqlite3.connect(data_path)
    conn2.execute("create table t1 (id int)")
    ds = Datasette(
        [data_path],
        internal=internal_path,
        config=instance_is_public and {"allow": {"id": "root"} or {}},
    )
    await ds.invoke_startup()
    cookies = {"ds_actor": ds.client.actor_cookie({"id": "root"})}
    response = await ds.client.get("/data", cookies=cookies)
    fragment = 'a href="/-/public-database/data">Change database visibility'
    if should_show_database_actions:
        assert fragment in response.text
    else:
        assert fragment not in response.text

    # And fetch the control page
    response2 = await ds.client.get(
        "/-/public-database/data",
        cookies=cookies,
    )
    fragment2 = "cannot change the visibility"
    if should_show_database_actions:
        assert fragment2 not in response2.text
    else:
        assert fragment2 in response2.text
