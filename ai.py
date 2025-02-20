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
    SSLCertVerificationError,
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


def make_pinned_ssl_context(pinned_sha_256):
    """
    Returns an instance of a subclass of SSLContext that uses a subclass of SSLSocket
    that actually verifies the sha256 of the certificate during the TLS handshake
    Tested with `python-version: [3.8, 3.9, 3.10, 3.11, 3.12, 3.13]`
    Original code can be found at https://github.com/c4ffein/python-snippets
    """

    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:
                raise SSLCertVerificationError("Incorrect certificate checksum")

        def do_handshake(self, *args, **kwargs):
            r = super().do_handshake(*args, **kwargs)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

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
            context.load_default_certs(purpose)  # Try loading default system root CA certificates, may fail silently
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
            raise AIException("Timed out") from e
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
    # TODO Update Claude
    # TODO Add le Chat as far faster
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
