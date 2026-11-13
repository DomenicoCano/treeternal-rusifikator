#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Русификатор Treeternal (неофициальный).

Режимы:
  ru_patcher.exe                      - интерактивное меню (установить / удалить)
  ru_patcher.exe "путь\\treeternal.exe" - установить в указанный exe
  ru_patcher.exe %command%            - для параметров запуска Steam: при каждом
                                        запуске проверяет игру, при необходимости
                                        ставит перевод заново (после обновления)
                                        и запускает игру.
"""
import io, json, os, re, shutil, struct, subprocess, sys

import numpy as np
from PIL import Image

APP_NAME = "Treeternal"
BACKUP_SUFFIX = ".orig"
SECTION_NAME = b".odpk"
GAME_EXE = "treeternal.exe"
FONTS = ["m6x11", "m6x11plus", "y2k"]
M64 = (1 << 64) - 1
KEY = 0xA7C51D3E9B4F8206


# ---------------------------------------------------------------- ресурсы
def res_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "data", name)


def read_res(name):
    with open(res_path(name), "rb") as f:
        return f.read()


class PatchError(Exception):
    pass


# ---------------------------------------------------------------- шифр
def keystream(start, n):
    first = start >> 3
    last = (start + n - 1) >> 3
    blk = np.arange(first, last + 1, dtype=np.uint64)
    with np.errstate(over="ignore"):
        z = (blk * np.uint64(0x9E3779B97F4A7C15)) ^ np.uint64(KEY)
        z = (z ^ (z >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        z = (z ^ (z >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
        z = z ^ (z >> np.uint64(31))
    raw = z.astype("<u8").tobytes()
    off = start & 7
    return np.frombuffer(raw, dtype=np.uint8)[off:off + n]


def crypt(buf, start=0x20):
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    return (arr ^ keystream(start, len(arr))).tobytes()


# ---------------------------------------------------------------- архив ODPK
def fnv(s):
    h = 0xCBF29CE484222325
    for c in s.encode():
        h = ((h ^ c) * 0x100000001B3) & M64
    return h


def parse_archive(a):
    if a[:4] != b"ODPK" or struct.unpack_from("<I", a, 4)[0] != 2:
        raise PatchError("неизвестный формат архива игры")
    n = struct.unpack_from("<I", a, 8)[0]
    nb, nl = struct.unpack_from("<QQ", a, 16)
    ents = {}
    for k in range(n):
        h, o, s, x = struct.unpack_from("<QQQQ", a, 32 + k * 32)
        off, ln = x & 0xFFFFFFFF, x >> 32
        try:
            name = a[nb + off:nb + off + ln].decode()
        except UnicodeDecodeError:
            raise PatchError("не удалось расшифровать архив (возможно, поменялся ключ)")
        if fnv(name) != h or o + s > len(a):
            raise PatchError("не удалось расшифровать архив (возможно, поменялся ключ)")
        ents[name] = a[o:o + s]
    return ents


def pack_archive(ents):
    items = sorted(ents.items(), key=lambda kv: fnv(kv[0]))
    n = len(items)
    nb = 32 + n * 32
    names = b""
    noff = {}
    for nm, _ in items:
        noff[nm] = len(names)
        names += nm.encode()
    dstart = (nb + len(names) + 15) // 16 * 16
    out = bytearray(struct.pack("<4sIIIQQ", b"ODPK", 2, n, 1, nb, len(names)))
    off = dstart
    offs = {}
    for nm, d in items:
        offs[nm] = off
        off = (off + len(d) + 15) // 16 * 16
    for nm, d in items:
        out += struct.pack("<QQQQ", fnv(nm), offs[nm], len(d),
                           (len(nm.encode()) << 32) | noff[nm])
    out += names
    out += b"\0" * (dstart - len(out))
    for nm, d in items:
        out += d
        out += b"\0" * ((-len(out)) % 16)
    return bytes(out)


# ---------------------------------------------------------------- PE
class PE:
    def __init__(self, data):
        self.d = data
        if data[:2] != b"MZ":
            raise PatchError("это не exe-файл")
        self.pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.pe:self.pe + 4] != b"PE\0\0":
            raise PatchError("это не exe-файл")
        self.nsec_off = self.pe + 6
        self.nsec = struct.unpack_from("<H", data, self.nsec_off)[0]
        self.optsize = struct.unpack_from("<H", data, self.pe + 20)[0]
        self.opt = self.pe + 24
        if struct.unpack_from("<H", data, self.opt)[0] != 0x20B:
            raise PatchError("поддерживается только 64-битная версия игры")
        self.sec_off = self.opt + self.optsize
        self.secs = []
        for i in range(self.nsec):
            o = self.sec_off + i * 40
            name = data[o:o + 8].rstrip(b"\0")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            self.secs.append(dict(name=name, vsize=vsize, va=va, rawsize=rawsize, rawptr=rawptr))
        self.sa = struct.unpack_from("<I", data, self.opt + 32)[0]
        self.fa = struct.unpack_from("<I", data, self.opt + 36)[0]
        self.res_rva = struct.unpack_from("<I", data, self.opt + 112 + 2 * 8)[0]

    def rva2off(self, rva):
        for s in self.secs:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return rva - s["va"] + s["rawptr"]
        raise PatchError("повреждённый exe (RVA вне секций)")

    def section_of_rva(self, rva):
        for s in self.secs:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s
        return None

    def find_rcdata(self):
        """Возвращает (offset записи IMAGE_RESOURCE_DATA_ENTRY, rva данных, размер)."""
        d = self.d
        if not self.res_rva:
            raise PatchError("в exe нет ресурсов")
        base = self.rva2off(self.res_rva)

        def entries(off):
            nn, ni = struct.unpack_from("<HH", d, base + off + 12)
            for i in range(nn + ni):
                nm, o = struct.unpack_from("<II", d, base + off + 16 + i * 8)
                yield nm, o

        for nm, o in entries(0):
            if nm != 10 or not (o & 0x80000000):
                continue
            for _, o2 in entries(o & 0x7FFFFFFF):
                if not (o2 & 0x80000000):
                    continue
                for _, o3 in entries(o2 & 0x7FFFFFFF):
                    if o3 & 0x80000000:
                        continue
                    eoff = base + o3
                    rva, size = struct.unpack_from("<II", d, eoff)
                    off = self.rva2off(rva)
                    if d[off:off + 4] == b"ODPK":
                        return eoff, rva, size
        raise PatchError("в exe не найден архив ресурсов игры (ODPK)")


# ---------------------------------------------------------------- перевод
LOOK = dict(zip("аеорсху", "aeopcxy"))
OTHER = "бвгдёжзийклмнптфцчшщъыьэюя"
CODES = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12] + list(range(14, 32)) + [127]
CMAP = {c: chr(CODES[i]) for i, c in enumerate(OTHER)}
CMAP.update(LOOK)


def encode_text(s):
    out = []
    for ch in s:
        low = ch.lower() if "А" <= ch <= "Я" or ch == "Ё" else ch
        ch = CMAP.get(low, low)
        if ord(ch) >= 128:
            raise PatchError("в переводе есть символ без глифа: %r" % ch)
        out.append(ch)
    return "".join(out)


PH = re.compile(r"\{[^}]*\}")


def build_lang(en_bytes):
    txt = en_bytes.decode("utf-8-sig")
    en = json.loads(txt)
    if len(en) != 1:
        raise PatchError("неожиданный формат lang/en.json")
    code, strings = next(iter(en.items()))
    ru = json.loads(read_res("ru.json").decode("utf-8"))["ru"]
    out = {}
    missing = []
    for k, v in strings.items():
        r = ru.get(k)
        if r is not None and (PH.findall(r) == PH.findall(v) or sorted(PH.findall(r)) == sorted(PH.findall(v))):
            out[k] = encode_text(r)
        else:
            out[k] = v
            missing.append(k)
    # английские значения оставляем как есть (ASCII), русские уже закодированы
    data = json.dumps({code: out}, ensure_ascii=True, indent=4).encode("ascii")
    return data, missing


# ---------------------------------------------------------------- шрифты
def patch_font(name, jbytes, pbytes, meta):
    j = json.loads(jbytes.decode("utf-8-sig"))
    if any(g.get("unicode") == 1 for g in j["glyphs"]):
        return jbytes, pbytes  # уже пропатчен
    img = Image.open(io.BytesIO(pbytes))
    img.load()
    H0 = j["atlas"]["height"]
    W = j["atlas"]["width"]
    if W != meta["atlas_width"] or img.size != (W, H0):
        raise PatchError("атлас шрифта %s изменился в этой версии игры" % name)
    strip = Image.open(res_path("strip_%s.png" % name)).convert("RGB")
    if img.mode == "RGBA":
        strip = strip.convert("RGBA")
    elif img.mode != "RGB":
        img = img.convert("RGB")
    canvas = Image.new(img.mode, (W, H0 + strip.height))
    canvas.paste(strip, (0, 0))
    canvas.paste(img, (0, strip.height))
    for g in meta["glyphs"]:
        g = json.loads(json.dumps(g))
        g["atlasBounds"]["bottom"] += H0
        g["atlasBounds"]["top"] += H0
        j["glyphs"].append(g)
    j["atlas"]["height"] = H0 + strip.height
    buf = io.BytesIO()
    canvas.save(buf, "PNG", optimize=True)
    return json.dumps(j, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), buf.getvalue()


# ---------------------------------------------------------------- патч exe
def is_patched(data):
    pe = PE(data)
    _, rva, _ = pe.find_rcdata()
    s = pe.section_of_rva(rva)
    return bool(s and s["name"] == SECTION_NAME)


def patch_bytes(data, log=print):
    pe = PE(data)
    eoff, rva, size = pe.find_rcdata()
    sec = pe.section_of_rva(rva)
    if sec and sec["name"] == SECTION_NAME:
        raise PatchError("уже установлено")
    off = pe.rva2off(rva)
    arc = data[off:off + 32] + crypt(data[off + 32:off + size])
    ents = parse_archive(arc)
    for need in ["lang/en.json"] + ["fonts/%s.json" % f for f in FONTS] + ["textures/%s.png" % f for f in FONTS]:
        if need not in ents:
            raise PatchError("в этой версии игры нет файла %s" % need)
    lang, missing = build_lang(ents["lang/en.json"])
    ents["lang/en.json"] = lang
    meta = json.loads(read_res("glyphs.json"))
    for f in FONTS:
        jb, pb = patch_font(f, ents["fonts/%s.json" % f], ents["textures/%s.png" % f], meta[f])
        ents["fonts/%s.json" % f] = jb
        ents["textures/%s.png" % f] = pb
    new = pack_archive(ents)
    new = new[:32] + crypt(new[32:])

    out = bytearray(data)
    last = max(pe.secs, key=lambda s: s["va"])
    va = (last["va"] + last["vsize"] + pe.sa - 1) // pe.sa * pe.sa
    raw = (len(out) + pe.fa - 1) // pe.fa * pe.fa
    rawsize = (len(new) + pe.fa - 1) // pe.fa * pe.fa
    sh = pe.sec_off + 40 * pe.nsec
    first_raw = min(s["rawptr"] for s in pe.secs if s["rawptr"])
    if sh + 40 > first_raw or out[sh:sh + 40] != b"\0" * 40:
        raise PatchError("в заголовке exe нет места для новой секции")
    out[sh:sh + 40] = struct.pack("<8sIIIIIIHHI", SECTION_NAME, len(new), va, rawsize, raw, 0, 0, 0, 0, 0x40000040)
    out += b"\0" * (raw - len(out))
    out += new + b"\0" * (rawsize - len(new))
    struct.pack_into("<H", out, pe.nsec_off, pe.nsec + 1)
    struct.pack_into("<I", out, pe.opt + 56, (va + len(new) + pe.sa - 1) // pe.sa * pe.sa)
    struct.pack_into("<I", out, pe.opt + 64, 0)
    struct.pack_into("<II", out, eoff, va, len(new))
    return bytes(out), missing


def install(exe_path, log=print):
    with open(exe_path, "rb") as f:
        data = f.read()
    if is_patched(data):
        log("Перевод уже установлен.")
        return False
    log("Читаю архив игры и накладываю перевод...")
    new, missing = patch_bytes(data, log)
    backup = exe_path + BACKUP_SUFFIX
    try:
        with open(backup, "wb") as f:
            f.write(data)
        tmp = exe_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(new)
        os.replace(tmp, exe_path)
    except PermissionError:
        raise PatchError("не удалось записать файл. Закройте игру и запустите патчер снова.")
    log("Готово! Оригинал сохранён как %s" % os.path.basename(backup))
    if missing:
        log("Непереведённых строк (останутся английскими): %d" % len(missing))
    return True


def restore(exe_path, log=print):
    backup = exe_path + BACKUP_SUFFIX
    if not os.path.exists(backup):
        raise PatchError("резервная копия %s не найдена. Проверьте файлы игры в Steam." % os.path.basename(backup))
    try:
        shutil.copyfile(backup, exe_path)
    except PermissionError:
        raise PatchError("не удалось записать файл. Закройте игру и запустите патчер снова.")
    log("Оригинальный exe восстановлен.")


# ---------------------------------------------------------------- поиск игры
def steam_libraries():
    libs = []
    try:
        import winreg
        for hive, key in [(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam")]:
            try:
                with winreg.OpenKey(hive, key) as k:
                    for val in ("SteamPath", "InstallPath"):
                        try:
                            libs.append(winreg.QueryValueEx(k, val)[0])
                        except OSError:
                            pass
            except OSError:
                pass
    except ImportError:
        pass
    extra = []
    for l in libs:
        vdf = os.path.join(l, "steamapps", "libraryfolders.vdf")
        if os.path.exists(vdf):
            try:
                with open(vdf, encoding="utf-8", errors="ignore") as f:
                    for m in re.finditer(r'"path"\s+"([^"]+)"', f.read()):
                        extra.append(m.group(1).replace("\\\\", "\\"))
            except OSError:
                pass
    seen, out = set(), []
    for l in libs + extra:
        l = os.path.normpath(l)
        if l.lower() not in seen:
            seen.add(l.lower())
            out.append(l)
    return out


def find_games():
    found = []
    for lib in steam_libraries():
        common = os.path.join(lib, "steamapps", "common")
        if not os.path.isdir(common):
            continue
        for d in os.listdir(common):
            if d.lower().startswith("treeternal"):
                p = os.path.join(common, d, GAME_EXE)
                if os.path.exists(p):
                    found.append(p)
    return found


def ask_file():
    try:
        import tkinter
        from tkinter import filedialog
        root = tkinter.Tk()
        root.withdraw()
        p = filedialog.askopenfilename(title="Выберите treeternal.exe", filetypes=[("treeternal.exe", "*.exe")])
        root.destroy()
        return p or None
    except Exception:
        return None


# ---------------------------------------------------------------- main
def launch_mode(argv):
    exe = argv[0]
    try:
        install(exe, log=lambda s: None)
    except PatchError as e:
        print("[ru_patcher] перевод не установлен: %s" % e)
    except Exception as e:  # не мешаем запуску игры
        print("[ru_patcher] ошибка: %r" % e)
    rc = subprocess.call(argv, cwd=os.path.dirname(os.path.abspath(exe)))
    sys.exit(rc)


def pause():
    try:
        input("\nНажмите Enter для выхода...")
    except EOFError:
        pass


def menu():
    print("=" * 60)
    print(" Русификатор %s (неофициальный)" % APP_NAME)
    print("=" * 60)
    games = find_games()
    path = None
    if len(games) == 1:
        path = games[0]
        print("Найдена игра:\n  %s" % path)
    elif len(games) > 1:
        print("Найдено несколько установок:")
        for i, g in enumerate(games, 1):
            print("  %d) %s" % (i, g))
        try:
            n = int(input("Выберите номер: ").strip())
            path = games[n - 1]
        except (ValueError, IndexError, EOFError):
            print("Неверный выбор.")
            return
    else:
        print("Игра в Steam не найдена. Выберите treeternal.exe вручную.")
        path = ask_file()
        if not path:
            try:
                path = input("Или введите полный путь к treeternal.exe: ").strip().strip('"')
            except EOFError:
                path = None
        if not path or not os.path.isfile(path):
            print("Файл не найден.")
            return
    print()
    print("  1) Установить русификатор")
    print("  2) Удалить русификатор (вернуть оригинал)")
    print("  3) Выход")
    try:
        ch = input("Ваш выбор [1]: ").strip() or "1"
    except EOFError:
        ch = "1"
    try:
        if ch == "1":
            install(path)
            print("\nСовет: чтобы перевод не пропадал после обновлений игры, в Steam:")
            print("  Свойства игры -> Параметры запуска -> вставьте:")
            print('  "%s" %%command%%' % os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
        elif ch == "2":
            restore(path)
    except PatchError as e:
        print("Ошибка: %s" % e)


def main():
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    argv = sys.argv[1:]
    if argv and argv[0].lower().endswith(".exe") and os.path.exists(argv[0]) \
            and os.path.basename(argv[0]).lower() == GAME_EXE:
        if len(argv) > 1 or os.environ.get("SteamAppId") or os.environ.get("SteamGameId"):
            launch_mode(argv)
        try:
            install(argv[0])
        except PatchError as e:
            print("Ошибка: %s" % e)
        pause()
        return
    menu()
    pause()


if __name__ == "__main__":
    main()
