"""Ядро Cipher-X: формат CPX1 (общий с настольной версией) и активация."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import os
import secrets
import tempfile
import unicodedata
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterator, Optional, Tuple

# ════════════════════════════════════════════════════════════════════
#  Криптографическое ядро (формат CPX1, совместим с версией 2.0)
# ════════════════════════════════════════════════════════════════════

MAGIC = b"CPX1"
KEY_LEN = 32
SALT_LEN = 16
PREFIX_LEN = 7
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 2 + SALT_LEN + PREFIX_LEN

CHUNK_LOG2 = 20
SCRYPT_R = 8
SCRYPT_P = 1

MIN_N_LOG2, MAX_N_LOG2 = 14, 19
MIN_CHUNK_LOG2, MAX_CHUNK_LOG2 = 12, 24

ProgressFn = Callable[[int], None]


class CipherError(Exception):
    pass


class FormatError(CipherError):
    pass


class AuthError(CipherError):
    pass


class Cancelled(CipherError):
    pass


@dataclass(frozen=True)
class Level:
    id: int
    name: str
    n_log2: int
    hint: str

    @property
    def memory_mib(self) -> int:
        return 1 << (self.n_log2 - 10)


LEVELS = {
    lv.id: lv
    for lv in (
        Level(1, "Быстрый", 14, "Для слабых компьютеров и частых операций."),
        Level(2, "Обычный", 15, "Баланс скорости и стойкости."),
        Level(3, "Надёжный", 17, "Рекомендуется для большинства задач."),
        Level(4, "Максимальный", 18, "Наибольшая стойкость к подбору, ключ создаётся дольше."),
    )
}
DEFAULT_LEVEL = LEVELS[3]


def derive_key(password: str, salt: bytes, n_log2: int) -> bytes:
    secret = unicodedata.normalize("NFKC", password).encode("utf-8")
    n = 1 << n_log2
    try:
        return hashlib.scrypt(
            secret, salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P,
            maxmem=256 * SCRYPT_R * n, dklen=KEY_LEN,
        )
    except (AttributeError, ValueError):
        from Crypto.Protocol.KDF import scrypt
        return scrypt(secret, salt, KEY_LEN, N=n, r=SCRYPT_R, p=SCRYPT_P)


def _read_full(src: BinaryIO, size: int) -> bytes:
    buf = src.read(size)
    if not buf or len(buf) == size:
        return buf
    parts, got = [buf], len(buf)
    while got < size:
        more = src.read(size - got)
        if not more:
            break
        parts.append(more)
        got += len(more)
    return b"".join(parts)


def _blocks(src: BinaryIO, size: int) -> Iterator[Tuple[bytes, bool]]:
    block = _read_full(src, size)
    while True:
        nxt = _read_full(src, size)
        yield block, not nxt
        if not nxt:
            return
        block = nxt


def _cipher(key: bytes, prefix: bytes, index: int, last: bool, header: bytes):
    from Crypto.Cipher import AES
    if index >= 1 << 32:
        raise CipherError("Данные слишком велики для формата CPX1.")
    nonce = prefix + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    return cipher


def encrypt_stream(src: BinaryIO, dst: BinaryIO, password: str, n_log2: int,
                   progress: Optional[ProgressFn] = None) -> int:
    if not password:
        raise CipherError("Пароль не может быть пустым.")
    if not MIN_N_LOG2 <= n_log2 <= MAX_N_LOG2:
        raise CipherError("Недопустимый уровень безопасности.")

    salt = secrets.token_bytes(SALT_LEN)
    prefix = secrets.token_bytes(PREFIX_LEN)
    header = MAGIC + bytes((n_log2, CHUNK_LOG2)) + salt + prefix
    key = derive_key(password, salt, n_log2)
    if progress:
        progress(0)

    dst.write(header)
    done = 0
    for index, (block, last) in enumerate(_blocks(src, 1 << CHUNK_LOG2)):
        ct, tag = _cipher(key, prefix, index, last, header).encrypt_and_digest(block)
        dst.write(ct)
        dst.write(tag)
        done += len(block)
        if progress:
            progress(done)
    return done


def decrypt_stream(src: BinaryIO, dst: BinaryIO, password: str,
                   progress: Optional[ProgressFn] = None) -> int:
    if not password:
        raise CipherError("Пароль не может быть пустым.")

    header = _read_full(src, HEADER_LEN)
    if len(header) < HEADER_LEN or header[:len(MAGIC)] != MAGIC:
        raise FormatError("Это не контейнер Cipher-X (неверный формат или версия).")
    n_log2, chunk_log2 = header[4], header[5]
    if not (MIN_N_LOG2 <= n_log2 <= MAX_N_LOG2
            and MIN_CHUNK_LOG2 <= chunk_log2 <= MAX_CHUNK_LOG2):
        raise FormatError("Параметры контейнера повреждены.")
    salt = header[6:6 + SALT_LEN]
    prefix = header[6 + SALT_LEN:]

    key = derive_key(password, salt, n_log2)
    consumed = HEADER_LEN
    if progress:
        progress(consumed)

    total = 0
    for index, (block, last) in enumerate(_blocks(src, (1 << chunk_log2) + TAG_LEN)):
        if len(block) < TAG_LEN:
            raise AuthError("Файл обрезан или повреждён.")
        try:
            plain = _cipher(key, prefix, index, last, header).decrypt_and_verify(
                block[:-TAG_LEN], block[-TAG_LEN:])
        except ValueError:
            raise AuthError("Неверный пароль или данные повреждены/изменены.") from None
        dst.write(plain)
        total += len(plain)
        consumed += len(block)
        if progress:
            progress(consumed)
    return total


def encrypt_bytes(data: bytes, password: str, n_log2: int) -> bytes:
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, password, n_log2)
    return out.getvalue()


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, password)
    return out.getvalue()


def encrypt_text(text: str, password: str, n_log2: int) -> str:
    return base64.b64encode(encrypt_bytes(text.encode("utf-8"), password, n_log2)).decode("ascii")


def decrypt_text(token: str, password: str) -> str:
    cleaned = "".join(token.replace("\ufeff", "").split())
    try:
        blob = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        raise FormatError(
            "Текст не похож на шифртекст Cipher-X (ошибка Base64). "
            "Возможно, он скопирован не полностью."
        ) from None
    plain = decrypt_bytes(blob, password)
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("Данные расшифрованы, но это не текст — используйте раздел «Файлы».") from None


def _process_file(func, src_path: str, dst_path: str, password: str, *args) -> int:
    if os.path.exists(dst_path) and os.path.samefile(src_path, dst_path):
        raise CipherError("Исходный и целевой файлы совпадают.")
    directory = os.path.dirname(os.path.abspath(dst_path))
    with open(src_path, "rb") as fin:
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".cipherx-", suffix=".part")
        try:
            with os.fdopen(fd, "wb") as fout:
                count = func(fin, fout, password, *args)
                fout.flush()
                os.fsync(fout.fileno())
            os.replace(tmp_path, dst_path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    return count


def encrypt_file(src_path: str, dst_path: str, password: str, n_log2: int,
                 progress: Optional[ProgressFn] = None) -> int:
    return _process_file(encrypt_stream, src_path, dst_path, password, n_log2, progress)


def decrypt_file(src_path: str, dst_path: str, password: str,
                 progress: Optional[ProgressFn] = None) -> int:
    return _process_file(decrypt_stream, src_path, dst_path, password, progress)



ACTIVATION_SALT = b"cipher-x/activation/v1"
ACTIVATION_ITERATIONS = 200_000
ACCESS_CODE_HASH = "31c73c5ad6e55f2e4666a81fbad406f098bd78549a0be6158e9a4157f360b831"
# Хеш тестового кода. Перед раздачей программы удалите его из кортежа.
TEST_CODE_HASH = "8000543e64463ba82ca0976dbdc44dd48e5a5f94f57af6130e3401be7290ce2c"
ACCEPTED_CODE_HASHES = (ACCESS_CODE_HASH, TEST_CODE_HASH)
MAX_ACTIVATION_ATTEMPTS = 5
MIN_PASSWORD_LEN = 8
CPX_EXT = ".cpx"


def code_matches(code: str) -> bool:
    digest = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"),
                                 ACTIVATION_SALT, ACTIVATION_ITERATIONS).hex()
    return any([hmac.compare_digest(digest, h) for h in ACCEPTED_CODE_HASHES])
