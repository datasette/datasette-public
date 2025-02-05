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


def _get_public_tables(db_path):
    conn = sqlite3.connect(db_path)
    return [row[0] for row in conn.execute("select table_name from public_tables")]
