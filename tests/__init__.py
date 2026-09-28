"""Fail closed if any regression test accidentally opens production SQLite storage."""
from pathlib import Path
import sqlite3
import socket
import streamlit as st

# AppTest otherwise inherits local/global secrets when no test secrets are set.
# Bootstrap tests explicitly inject generated synthetic configurations.
st.secrets = {}

_connect = sqlite3.connect
_production = Path(__file__).resolve().parent.parent / 'data'


def _temporary_connect(database, *args, **kwargs):
    value = str(database)
    if value.startswith('file:'):
        # Tests do not need URI databases; disallow alternate path spellings.
        raise AssertionError('SQLite URI connections are forbidden in tests.')
    if value != ':memory:' and Path(value).resolve().is_relative_to(_production):
        raise AssertionError('Tests must never open production storage.')
    return _connect(database, *args, **kwargs)


sqlite3.connect = _temporary_connect


def _no_network(*args, **kwargs):
    raise AssertionError('Network access is forbidden throughout the test suite.')


socket.socket.connect = _no_network
socket.socket.connect_ex = _no_network
socket.socket.sendto = _no_network
socket.create_connection = _no_network
socket.getaddrinfo = _no_network
