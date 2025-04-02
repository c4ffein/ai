#!/usr/bin/env python

"""
ai - KISS cli to connect to remote conversational AI
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
TODOs and possible improvements: Fill this
"""

import os
from base64 import b64encode
from enum import Enum
from hashlib import sha256
from json import dumps, loads
from mimetypes import guess_type
from pathlib import Path
from socket import gaierror
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
from urllib.error import HTTPError
from urllib.request import Request, urlopen

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])


CLAUDE_MODELS = [
    ["claude-3-7-sonnet-latest"],
    ["claude-3-7-haiku-latest"],
    ["claude-3-5-sonnet-20241022"],
    ["claude-3-5-haiku-20241022"],
    ["claude-3-opus-20240229"],
    ["claude-3-sonnet-20240229"],
    ["claude-3-haiku-20240229"],
]


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


def post_body_to_claude(cert_checksum, api_key, json, timeout=30):
    context = make_pinned_ssl_context(cert_checksum)
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",  # API feature lock
        "User-Agent": "",  # Otherwise would send default User-Agent
        "Content-Type": "application/json",
    }
    body = dumps(json).encode()  # TODO Good encoding, check headers
    request = Request("https://api.anthropic.com/v1/messages", body, headers=headers)
    try:
        response = urlopen(request, context=context, timeout=timeout)
        r = response.read()
    except HTTPError as exc:
        raise AIException(f"HTTP Error when reaching Claude: {exc.code}") from exc
    except socket_timeout as exc:
        raise AIException("Timed out") from exc
    except Exception as exc:
        if isinstance(getattr(exc, "reason", None), socket_timeout):
            raise AIException("TLS timed out") from exc  # Most probable cause, should check this is always the case
        if isinstance(getattr(exc, "reason", None), gaierror):
            raise AIException("Failed domain name resolution") from exc
        if isinstance(getattr(exc, "reason", None), SSLCertVerificationError):
            raise AIException("Failed SSL cert validation") from exc
        # Keeping this as-is for now, should not happen if everything is handled correctly, add any necessary ones
        raise AIException("Unknown error when trying to reach Claude") from exc
    try:
        return loads(r)
    except Exception as exc:
        raise AIException("Unable to parse JSON answer from the response") from exc


def usage(wrong_config=False):
    output_lines = [
        "ai - KISS LLM bridge to your terminal",
        "=====================================",
        """~/.config/ai/config.json => {"api-key": "sk-ant-XXXX", "certificate": "XXXX"}""",
        "=======================",
        """- ai                              ==> show usage""",
        """- ai "A question"                 ==> ask something""",
        """- ai "A question" file="file.md"  ==> ask something with an additional file""",
        "=======================",
        "Only reaching out to Claude for now, will maybe add Le Chat from Mistral",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def ask_claude(certificate: str, api_key: str, prompt: str, max_tokens: int = 10000, files=None) -> Dict[str, Any]:
    b64_file = lambda file: b64encode(Path(file).read_bytes()).decode()
    get_file = lambda file: (
        {"type": "document", "source": {"type": "base64", "media_type": guess_type(file)[0], "data": b64_file(file)}}
        if guess_type(file)[0] == "application/pdf"
        else {"type": "text", "text": Path(file).read_text()}
    )
    content = [{"type": "text", "text": prompt}, *[get_file(file) for file in (files if files is not None else [])]]
    data = {
        "model": CLAUDE_MODELS[0][0],  # TODO
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt if files is None else content}],
    }
    return post_body_to_claude(certificate, api_key, json=data, timeout=150)


def extract_response(api_response: Dict[str, Any]) -> tuple[Optional[str], bool]:
    try:
        return api_response["content"][0]["text"], api_response["stop_reason"] == "max_tokens"
    except (KeyError, IndexError) as err:
        raise AIException("Unexpected API response format") from err


def consume_args():
    if len(argv) <= 1:
        return True, None, None
    prompt = None
    files = []
    for arg in argv[1:]:
        if arg.startswith("file="):
            file_path = Path(arg[5:])
            if not file_path.is_file():
                raise AIException(f"File {file_path} does not exist")
            files.append(file_path)
            continue
        elif prompt is not None:
            raise AIException("Multiple prompts detected, currently not allowed")
        prompt = arg
    return False, prompt, files or None


def main():
    usage_required, prompt, files = consume_args()
    if usage_required:
        return usage()
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
    response = ask_claude(certificate, api_key, prompt, files=files)
    answer, stopped_reasoning = extract_response(response)
    print(answer)
    if stopped_reasoning:
        raise AIException("Reached tokens limit")


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n")
        exit(-2)
    except AIException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(-1)
    except Exception:
        raise
