#!/usr/bin/env python

"""
ai - KISS cli to connect to remote conversational AI
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
TODOs and possible improvements: Fill this
"""

import os
from enum import Enum
from hashlib import sha256
from json import dumps, loads
from pathlib import Path
from socket import timeout as socket_timeout
from ssl import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Purpose,
    SSLContext,
    SSLSocket,
    _ASN1Object,
    _ssl,
)
from sys import argv, exit
from sys import flags as sys_flags
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])
COLOR_LEN = 4


# TODO : UT to ensure the checks are called for any python version
# TODO : UT to ensure those works if we create 2 contexts with 2 different certificatesa
# TODO : UT to ensure check is called if already opened socket gets wrapped
# TODO : UT to ensure check is called if connecting on new socket
# TODO : Ensure called with correct params, so that regular verif, and so getpeercert is enough
def make_pinned_ssl_context(pinned_sha_256):
    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:  # TODO : Check this is enough
                raise Exception("Incorrect certificate checksum")  # TODO : Better

        def connect(self, addr):  # Needed for when the context creates a new connection
            r = super().connect(addr)
            self.check_pinned_cert()
            return r

        def connect_ex(self, addr):  # Needed for when the context creates a new connection
            r = super().connect_ex(addr)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

        def wrap_socket(  # Needed for when we wrap an exising socket
            self,
            sock,
            server_side=False,
            do_handshake_on_connect=True,
            suppress_ragged_eofs=True,
            server_hostname=None,
            session=None,
        ):
            ws = super().wrap_socket(
                sock,
                server_side=server_side,
                do_handshake_on_connect=do_handshake_on_connect,
                suppress_ragged_eofs=suppress_ragged_eofs,
                server_hostname=server_hostname,
                session=session,
            )
            ws.check_pinned_cert()
            return ws

    def create_pinned_default_context(purpose=Purpose.SERVER_AUTH, *, cafile=None, capath=None, cadata=None):
        if not isinstance(purpose, _ASN1Object):
            raise TypeError(purpose)
        if purpose == Purpose.SERVER_AUTH:  # Verify certs and host name in client mode
            context = PinnedSSLContext(PROTOCOL_TLS_CLIENT)
            context.verify_mode, context.check_hostname = CERT_REQUIRED, True
        elif purpose == Purpose.CLIENT_AUTH:
            context = PinnedSSLContext(PROTOCOL_TLS_SERVER)
        else:
            raise ValueError(purpose)
        context.verify_flags |= _ssl.VERIFY_X509_STRICT
        if cafile or capath or cadata:
            context.load_verify_locations(cafile, capath, cadata)
        elif context.verify_mode != CERT_NONE:
            context.load_default_certs(
                purpose
            )  # Try loading default system root CA certificates, this may fail silently.
        if hasattr(context, "keylog_filename"):  # OpenSSL 1.1.1 keylog file
            keylogfile = os.environ.get("SSLKEYLOGFILE")
            if keylogfile and not sys_flags.ignore_environment:
                context.keylog_filename = keylogfile
        return context

    return create_pinned_default_context()


class AIException(Exception):
    pass


def post_body(cert_checksum, api_key, addr, url, json, timeout=30):
    context = make_pinned_ssl_context(cert_checksum)
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "User-Agent": "",  # Otherwise would send default User-Agent
        "Content-Type": "application/json",
    }
    body = dumps(json).encode()  # TODO Good encoding, check headers
    request = Request("https://" + (addr + url).decode(), body, headers=headers)
    try:
        r = urlopen(request, context=context, timeout=timeout)  # TODO data doesnt work?
    except Exception as e:
        if isinstance(getattr(e, "reason", None), socket_timeout):
            raise AIException("Timed out")
        raise e  # TODO Better
    return loads(r.read())  # TODO Secure


def usage(wrong_config=False, wrong_command=False, wrong_arg_len=False):
    output_lines = [
        "ai - KISS LLM bridge to your terminal",
        "=====================================",
        # TODO
        """~/.config/ai/config.json => TODO""",
        "=======================",
        "- ai                                ==> first test",
        "=======================",
        "This should help you get files TODO",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def ask_claude(certificate: str, api_key: str, prompt: str, max_tokens: int = 1000) -> Dict[str, Any]:
    data = {
        "model": "claude-3-sonnet-20240229",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    return post_body(  # TODO handle all errors
        certificate,
        api_key,
        b"api.anthropic.com",
        b"/v1/messages",
        json=data,
        timeout=30,
    )


def extract_response(api_response: Dict[str, Any]) -> Optional[str]:
    try:
        return api_response["content"][0]["text"]
    except (KeyError, IndexError) as err:
        raise AIException("Unexpected API response format") from err


def main():
    arg = argv[1] if len(argv) > 1 else "friend?"
    # TODO Input from args
    # TODO Input from read
    # TODO Shift \n for newline
    # TODO Arrows
    # TODO ctrl A/E
    # TODO \command
    try:
        with (Path.home() / ".config" / "ai" / "config.json").open() as f:
            config_content = f.read()  # TODO : HANDLE
        config_dict = loads(config_content)
        api_key = config_dict["api-key"]
        certificate = config_dict["certificate"]
        assert len(certificate) == 64  # TODO : BETTER
    except Exception:
        return usage(wrong_config=True)
    response = ask_claude(certificate, api_key, arg)
    answer = extract_response(response)
    print(answer)


if __name__ == "__main__":
    try:
        main()
    except AIException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(-1)
    except Exception:
        raise
