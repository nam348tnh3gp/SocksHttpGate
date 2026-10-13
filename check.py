#!/usr/bin/env python3
"""
check_go_validity.py (v2)

Kiểm tra tính hợp lệ của mã nguồn Go.

CHIẾN LƯỢC:
  1. Kiểm tra Go bằng cách CHẠY THẬT lệnh `go version` (không chỉ dò PATH
     bằng shutil.which, vì cách đó không đáng tin cậy trên một số thiết bị/
     shell: PATH của subprocess có thể khác PATH hệ thống, hoặc go được cài
     qua version manager/shim chỉ hoạt động khi thực thi trực tiếp). Nếu
     chạy được, script dùng go THẬT (`go vet` + `go build -o /dev/null`) để
     có kết quả chính xác 100% — đây là cách duy nhất đáng tin cậy tuyệt đối.
  2. Nếu KHÔNG có Go, script rơi về chế độ "heuristic static checker" bằng
     Python thuần: không thể thay thế hoàn toàn go build/go vet (không có
     type system, không resolve toàn bộ package, không biết chữ ký hàm của
     standard library...), nhưng bắt được nhiều lớp lỗi phổ biến hơn bản cũ:

     - Cân bằng ngoặc () {} [], chuỗi/rune/comment chưa đóng, package decl
     - Dấu '{' đứng một mình đầu dòng ngay sau dòng kết thúc bằng token có
       thể bị chèn dấu ';' tự động (ASI) -> lỗi "unexpected newline before {"
     - ':=' xuất hiện ở top-level (ngoài mọi hàm) -> luôn là lỗi cú pháp
     - Import bị khai báo nhưng không dùng ở đâu trong file (heuristic
       theo package identifier, không resolve alias phức tạp)
     - Struct literal gán field kiểu cơ bản (int/int64/string/...) từ biến
       'var x <type>' có kiểu cơ bản KHÁC kiểu field khai báo trong struct
       (đây chính là lớp lỗi bạn từng gặp: int64 gán vào field int)

  KHÔNG bắt được (giới hạn thật sự, không có compiler thì không có cách nào
  chắc chắn 100%): type inference đầy đủ (biến khai báo qua ':=' từ kết quả
  hàm), generic constraints, interface satisfaction, unresolved symbol từ
  package ngoài, shadowing phức tạp, v.v.

Cách dùng:
    python3 check_go_validity.py [path/to/file_or_dir ...]

Không truyền tham số -> tự tìm *.go trong thư mục hiện tại (đệ quy).
"""

import sys
import os
import re
import glob
import subprocess
import time
import json


# ---------------------------------------------------------------------------
# 0. Thử dùng Go thật nếu có
# ---------------------------------------------------------------------------

def detect_go():
    """Kiểm tra Go bằng cách CHẠY THẬT 'go version' thay vì chỉ dò PATH
    (shutil.which). Dò PATH không đáng tin cậy trên một số thiết bị/shell
    (PATH của subprocess có thể khác PATH hiển thị, alias, wrapper script,
    version manager như goenv/asdf chỉ hoạt động qua shim khi thực thi...).
    Trả về chuỗi version nếu chạy được, None nếu không."""
    try:
        r = subprocess.run(
            ["go", "version"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
        return None
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return None


def try_real_go(paths):
    version = detect_go()
    if not version:
        return None  # không chạy được go -> báo hiệu để rơi về heuristic

    print(f"[INFO] Go khả dụng ({version}) -> dùng go build / go vet thật.\n")
    env_info = get_go_env()
    if env_info:
        print(f"[INFO] GOOS={env_info.get('GOOS')} GOARCH={env_info.get('GOARCH')} "
              f"GOMOD={env_info.get('GOMOD') or '(không có go.mod)'} "
              f"CGO_ENABLED={env_info.get('CGO_ENABLED')}\n")

    ok = True
    for p in paths:
        pkg_info = get_package_info(p)

        print(f"=== go vet: {p} ===")
        cmd = ["go", "vet", p]
        t0 = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - t0
        out = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            ok = False
            print_go_failure(cmd, r.returncode, out, elapsed)
        else:
            print(f"  OK (go vet không thấy vấn đề) — {elapsed:.2f}s")
            if pkg_info:
                print(f"    Package: {pkg_info['name']}")
                print(f"    Số file .go: {pkg_info['go_file_count']} "
                      f"({', '.join(pkg_info['go_files'][:8])}"
                      f"{', ...' if pkg_info['go_file_count'] > 8 else ''})")
                if pkg_info['imports']:
                    print(f"    Số import (trực tiếp): {len(pkg_info['imports'])}")

        print(f"=== go build (kiểm tra, không tạo binary): {p} ===")
        tmp_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".go_validity_check_bin")
        cmd = ["go", "build", "-buildvcs=false", "-v", "-o", tmp_out, p]
        t0 = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - t0
        out = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            ok = False
            print_go_failure(cmd, r.returncode, out, elapsed)
        else:
            size_str = ""
            if os.path.isfile(tmp_out):
                size_bytes = os.path.getsize(tmp_out)
                size_str = f", binary {format_size(size_bytes)}"
                os.remove(tmp_out)
            compiled_pkgs = [ln.strip() for ln in out.splitlines() if ln.strip()]
            print(f"  OK (go build thành công) — {elapsed:.2f}s{size_str}")
            if compiled_pkgs:
                shown = compiled_pkgs[:10]
                print(f"    Package đã build: {', '.join(shown)}"
                      f"{f' (+{len(compiled_pkgs) - 10} khác)' if len(compiled_pkgs) > 10 else ''}")
        print()
    return ok


def get_go_env():
    try:
        r = subprocess.run(["go", "env", "GOOS", "GOARCH", "GOMOD", "CGO_ENABLED"],
                            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        vals = r.stdout.strip().splitlines()
        keys = ["GOOS", "GOARCH", "GOMOD", "CGO_ENABLED"]
        return dict(zip(keys, vals))
    except Exception:
        return None


# Các mẫu lỗi go build/go vet hay gặp -> gợi ý sửa cụ thể bằng tiếng Việt
ERROR_SUGGESTIONS = [
    (re.compile(r'C source files not allowed when not using cgo'),
     "Có file .c/.h nằm trong thư mục package Go nhưng cgo đang tắt. "
     "Cách sửa: di chuyển file C ra khỏi thư mục, hoặc nếu thực sự cần gọi C, "
     "thêm 'import \"C\"' vào file .go liên quan và chạy với CGO_ENABLED=1."),
    (re.compile(r'obtaining VCS status|not using a known version control system'),
     "Thư mục không nằm trong repo git được nhận diện. Đã tự thêm -buildvcs=false, "
     "nếu vẫn gặp lỗi này thì thử chạy 'git init' trong thư mục dự án hoặc kiểm tra "
     "thư mục .git có bị hỏng không."),
    (re.compile(r'go\.mod file not found|cannot find module'),
     "Thiếu file go.mod ở thư mục gốc dự án. Cách sửa: chạy 'go mod init <tên-module>' "
     "trong thư mục dự án trước."),
    (re.compile(r'no required module provides package|missing go\.sum entry'),
     "Thiếu dependency trong go.mod/go.sum. Cách sửa: chạy 'go mod tidy' để tự động "
     "thêm các package còn thiếu."),
    (re.compile(r'undefined:\s*(\w+)'),
     "Có identifier chưa được khai báo (biến/hàm/type dùng nhưng chưa định nghĩa, "
     "hoặc thiếu import). Kiểm tra chính tả và import ở các dòng lỗi bên trên."),
    (re.compile(r'imported and not used'),
     "Có import khai báo nhưng không dùng trong file — xoá dòng import đó hoặc dùng '_' "
     "nếu chỉ cần side-effect (blank import)."),
    (re.compile(r'declared (and|but) not used'),
     "Có biến khai báo nhưng không dùng — Go không cho phép biến local thừa. "
     "Xoá biến hoặc dùng '_ = tenBien' nếu cố tình bỏ qua."),
    (re.compile(r'cannot use .* as .* value'),
     "Sai kiểu dữ liệu khi gán giá trị (ví dụ int64 gán vào field/biến kiểu int). "
     "Cần ép kiểu tường minh, ví dụ: int(tenBien)."),
    (re.compile(r'multiple-value .* in single-value context'),
     "Một hàm trả về nhiều giá trị (ví dụ (value, error)) nhưng đang được dùng như thể "
     "chỉ có một giá trị. Cần gán đủ số biến, ví dụ: v, err := ..."),
    (re.compile(r'syntax error: unexpected newline, expecting \{'),
     "Dấu '{' bị đặt xuống dòng riêng (func/if/for/...). Trong Go, '{' phải nằm cùng "
     "dòng với khai báo phía trước."),
]


def diagnose_error(output):
    suggestions = []
    for pattern, advice in ERROR_SUGGESTIONS:
        if pattern.search(output):
            suggestions.append(advice)
    return suggestions


def print_go_failure(cmd, returncode, output, elapsed):
    print(f"  LỖI (exit code {returncode}) — {elapsed:.2f}s")
    print(f"    Lệnh đã chạy: {' '.join(cmd)}")
    print(f"    Thư mục làm việc: {os.getcwd()}")
    print("    --- Output ---")
    for ln in (output or "(không có output)").splitlines():
        print(f"    {ln}")
    file_lines = re.findall(r'([^\s:]+\.go):(\d+)(?::(\d+))?', output)
    if file_lines:
        print(f"    -> {len(file_lines)} vị trí lỗi cụ thể trong file .go (xem output ở trên).")
    suggestions = diagnose_error(output)
    if suggestions:
        print("    --- Gợi ý sửa ---")
        for s in suggestions:
            print(f"    • {s}")


def format_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def get_package_info(p):
    """Dùng 'go list -json' để lấy thông tin package: tên, danh sách file .go,
    import trực tiếp. Trả về None nếu go list thất bại (không chặn luồng chính)."""
    try:
        r = subprocess.run(
            ["go", "list", "-json", p],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout)
        go_files = data.get("GoFiles", []) or []
        return {
            "name": data.get("ImportPath") or data.get("Name") or p,
            "go_files": go_files,
            "go_file_count": len(go_files),
            "imports": data.get("Imports", []) or [],
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. Lexer: tạo bản "masked" của source (che nội dung string/comment/rune
#    bằng khoảng trắng, giữ nguyên độ dài + số dòng) để regex phía sau chạy
#    an toàn mà không bị nhầm nội dung trong chuỗi/comment.
# ---------------------------------------------------------------------------

def mask_source(text):
    n = len(text)
    out = list(text)
    errors = []
    i = 0
    line = 1

    def line_at(pos):
        return text.count('\n', 0, pos) + 1

    while i < n:
        c = text[i]

        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = i
            while j < n and text[j] != '\n':
                out[j] = ' '
                j += 1
            i = j
            continue

        if c == '/' and i + 1 < n and text[i + 1] == '*':
            start = i
            j = i + 2
            closed = False
            while j < n:
                if text[j] == '*' and j + 1 < n and text[j + 1] == '/':
                    j += 2
                    closed = True
                    break
                j += 1
            for k in range(start, min(j, n)):
                if text[k] != '\n':
                    out[k] = ' '
            if not closed:
                errors.append(f"Dòng {line_at(start)}: block comment '/*' không được đóng bằng '*/'")
            i = j
            continue

        if c == '"':
            start = i
            j = i + 1
            closed = False
            while j < n:
                if text[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '\n':
                    break
                if text[j] == '"':
                    j += 1
                    closed = True
                    break
                j += 1
            for k in range(start, min(j, n)):
                if text[k] != '\n':
                    out[k] = ' '
            if not closed:
                errors.append(f"Dòng {line_at(start)}: chuỗi \" chưa được đóng")
            i = j
            continue

        if c == '`':
            start = i
            j = i + 1
            closed = False
            while j < n:
                if text[j] == '`':
                    j += 1
                    closed = True
                    break
                j += 1
            for k in range(start, min(j, n)):
                if text[k] != '\n':
                    out[k] = ' '
            if not closed:
                errors.append(f"Dòng {line_at(start)}: raw string ` chưa được đóng")
            i = j
            continue

        if c == "'":
            start = i
            j = i + 1
            closed = False
            while j < n:
                if text[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '\n':
                    break
                if text[j] == "'":
                    j += 1
                    closed = True
                    break
                j += 1
            for k in range(start, min(j, n)):
                if text[k] != '\n':
                    out[k] = ' '
            if not closed:
                errors.append(f"Dòng {line_at(start)}: rune ' chưa được đóng")
            i = j
            continue

        i += 1

    return ''.join(out), errors


def lineno(text, pos):
    return text.count('\n', 0, pos) + 1


def mask_comments_only(text):
    """Giống mask_source nhưng CHỈ che comment (// và /* */), giữ nguyên
    nội dung string/rune. Dùng cho các chỗ cần đọc string literal thật
    (ví dụ đường dẫn import) mà vẫn muốn bỏ qua comment."""
    n = len(text)
    out = list(text)
    i = 0
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = i
            while j < n and text[j] != '\n':
                out[j] = ' '
                j += 1
            i = j
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            j = i + 2
            while j < n:
                if text[j] == '*' and j + 1 < n and text[j + 1] == '/':
                    j += 2
                    break
                j += 1
            for k in range(i, min(j, n)):
                if text[k] != '\n':
                    out[k] = ' '
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '\n':
                    break
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        i += 1
    return ''.join(out)


# ---------------------------------------------------------------------------
# 2. Bracket balance (trên bản masked)
# ---------------------------------------------------------------------------

def check_brackets(masked):
    pairs = {')': '(', ']': '[', '}': '{'}
    openers = set(pairs.values())
    stack = []
    errors = []
    for idx, c in enumerate(masked):
        if c in openers:
            stack.append((c, idx))
        elif c in pairs:
            if not stack:
                errors.append(f"Dòng {lineno(masked, idx)}: dấu đóng '{c}' dư thừa")
                continue
            top_c, top_idx = stack[-1]
            if pairs[c] != top_c:
                errors.append(
                    f"Dòng {lineno(masked, idx)}: dấu đóng '{c}' không khớp dấu mở '{top_c}' "
                    f"ở dòng {lineno(masked, top_idx)}"
                )
            stack.pop()
    for c, idx in stack:
        errors.append(f"Dòng {lineno(masked, idx)}: dấu mở '{c}' chưa được đóng")
    return errors


def check_package_declaration(masked):
    for ln in masked.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith('package '):
            return []
        return ["Không tìm thấy khai báo 'package <tên>' hợp lệ ở đầu file"]
    return ["File rỗng hoặc không có nội dung code"]


# ---------------------------------------------------------------------------
# 3. '{' đứng một mình đầu dòng, ngay sau dòng có thể bị ASI chèn ';'
# ---------------------------------------------------------------------------

ASI_TRIGGER_END = re.compile(r'([\w\]\)\}]|"|\`|\')\s*$')
# đơn giản hóa: word char, ), ], } ở cuối dòng trước => rủi ro ASI

def check_lone_brace(masked):
    errors = []
    lines = masked.splitlines()
    prev_nonblank = None
    for idx, ln in enumerate(lines, start=1):
        stripped = ln.strip()
        if not stripped:
            continue
        if stripped == '{':
            if prev_nonblank is not None and ASI_TRIGGER_END.search(prev_nonblank):
                errors.append(
                    f"Dòng {idx}: dấu '{{' đứng một mình đầu dòng ngay sau dòng kết thúc bằng "
                    f"token có thể bị Go tự chèn dấu ';' (ASI) -> khả năng cao lỗi cú pháp "
                    f"kiểu 'unexpected newline before {{'. '{{' nên nằm cùng dòng với func/if/for/struct/..."
                )
        prev_nonblank = stripped
    return errors


# ---------------------------------------------------------------------------
# 4. ':=' ở top-level (ngoài mọi hàm) -> luôn sai
# ---------------------------------------------------------------------------

def check_top_level_short_decl(masked):
    errors = []
    depth = 0
    i = 0
    n = len(masked)
    while i < n:
        c = masked[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        elif c == ':' and i + 1 < n and masked[i + 1] == '=' and depth == 0:
            errors.append(
                f"Dòng {lineno(masked, i)}: toán tử ':=' xuất hiện ở top-level (ngoài mọi hàm/block) "
                f"-> luôn là lỗi cú pháp trong Go"
            )
        i += 1
    return errors


# ---------------------------------------------------------------------------
# 5. Import khai báo nhưng có vẻ không dùng
# ---------------------------------------------------------------------------

IMPORT_BLOCK_RE = re.compile(r'import\s*\(\s*(.*?)\)', re.S)
IMPORT_SINGLE_RE = re.compile(r'import\s+("[^"]*")')
IMPORT_LINE_RE = re.compile(r'(?:(\w+)\s+)?"([^"]+)"')


def check_unused_imports(masked, comments_only_masked):
    """masked: bản che cả string lẫn comment (dùng để tìm usage 'ident.').
    comments_only_masked: bản chỉ che comment, giữ nguyên string (dùng để
    đọc chính xác đường dẫn import, vì import path bị 'masked' che mất)."""
    errors = []
    imported = []  # (ident, full_path, pos)

    block_match = IMPORT_BLOCK_RE.search(comments_only_masked)
    block_span = None
    if block_match:
        block_span = block_match.span()
        for line_match in IMPORT_LINE_RE.finditer(block_match.group(1)):
            alias, path = line_match.groups()
            ident = alias if alias else path.rstrip('/').split('/')[-1]
            imported.append((ident, path, block_match.start(1) + line_match.start()))

    for m in IMPORT_SINGLE_RE.finditer(comments_only_masked):
        if block_span and block_span[0] <= m.start() < block_span[1]:
            continue
        path = m.group(1).strip('"')
        ident = path.rstrip('/').split('/')[-1]
        imported.append((ident, path, m.start()))

    rest = masked
    if block_span:
        rest = masked[:block_span[0]] + ' ' * (block_span[1] - block_span[0]) + masked[block_span[1]:]

    for ident, path, pos in imported:
        if ident in ('_', '.'):
            continue
        usage_re = re.compile(r'\b' + re.escape(ident) + r'\s*\.')
        if not usage_re.search(rest):
            errors.append(
                f"Dòng {lineno(comments_only_masked, pos)}: import \"{path}\" có vẻ không được dùng ở đâu "
                f"trong file (không thấy '{ident}.' xuất hiện) -> go build sẽ báo lỗi 'imported and not used'"
            )
    return errors


# ---------------------------------------------------------------------------
# 6. Struct literal gán field kiểu cơ bản khác kiểu khai báo
#    (lớp lỗi giống ví dụ int64 -> int đã gặp trước đó)
# ---------------------------------------------------------------------------

BASIC_TYPES_NORM = {
    "byte": "uint8", "rune": "int32",
}
BASIC_TYPES = {
    "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
    "float32", "float64", "string", "bool", "byte", "rune",
}


def norm_type(t):
    return BASIC_TYPES_NORM.get(t, t)


def find_matching_brace(masked, open_pos):
    depth = 0
    i = open_pos
    n = len(masked)
    while i < n:
        if masked[i] == '{':
            depth += 1
        elif masked[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


STRUCT_DEF_RE = re.compile(r'\btype\s+(\w+)\s+struct\s*\{')
FIELD_RE = re.compile(r'^\s*(\w+)\s+(\*?)(\w+)\s*$', re.M)
VAR_DECL_RE = re.compile(
    r'\bvar\s+(\w+)\s+(\*?)(' + '|'.join(BASIC_TYPES) + r')\b'
)
FIELD_ASSIGN_RE = re.compile(r'\b(\w+)\s*:\s*(\w+)\s*[,\}]')


def extract_struct_defs(masked):
    structs = {}
    for m in STRUCT_DEF_RE.finditer(masked):
        name = m.group(1)
        open_brace = m.end() - 1
        close_brace = find_matching_brace(masked, open_brace)
        if close_brace == -1:
            continue
        body = masked[open_brace + 1:close_brace]
        fields = {}
        for fm in FIELD_RE.finditer(body):
            fname, ptr, ftype = fm.groups()
            if ftype in BASIC_TYPES and not ptr:
                fields[fname] = norm_type(ftype)
        structs[name] = fields
    return structs


def extract_var_types(masked):
    var_types = {}
    for m in VAR_DECL_RE.finditer(masked):
        name, ptr, t = m.groups()
        if not ptr:
            var_types[name] = norm_type(t)
    return var_types


def check_struct_literal_type_mismatch(masked):
    errors = []
    structs = extract_struct_defs(masked)
    if not structs:
        return errors
    var_types = extract_var_types(masked)

    for struct_name, fields in structs.items():
        if not fields:
            continue
        # tìm các literal "StructName{" mà KHÔNG phải "type StructName struct {"
        for m in re.finditer(r'\b' + re.escape(struct_name) + r'\s*\{', masked):
            pre = masked[max(0, m.start() - 6):m.start()]
            if 'type ' in pre:
                continue
            open_brace = m.end() - 1
            close_brace = find_matching_brace(masked, open_brace)
            if close_brace == -1:
                continue
            body = masked[open_brace + 1:close_brace]
            for fm in FIELD_ASSIGN_RE.finditer(body):
                fname, expr = fm.groups()
                if fname not in fields:
                    continue
                field_type = fields[fname]
                if expr in var_types:
                    expr_type = var_types[expr]
                    if expr_type != field_type:
                        pos = open_brace + 1 + fm.start()
                        errors.append(
                            f"Dòng {lineno(masked, pos)}: struct '{struct_name}' field '{fname}' "
                            f"khai báo kiểu '{field_type}' nhưng được gán biến '{expr}' có kiểu "
                            f"'{expr_type}' (khai báo qua 'var {expr} {expr_type}') -> khả năng cao "
                            f"lỗi 'cannot use {expr} (variable of type {expr_type}) as {field_type} value'"
                        )
    return errors


# ---------------------------------------------------------------------------
# 7. Cảnh báo thụt lề (không tính là lỗi)
# ---------------------------------------------------------------------------

def check_indentation(text):
    warnings = []
    for idx, ln in enumerate(text.splitlines(), start=1):
        if ln.startswith(' ') and not ln.startswith('\t') and ln.strip():
            warnings.append(idx)
    return warnings


# ---------------------------------------------------------------------------
# Main per-file
# ---------------------------------------------------------------------------

def gather_file_stats(text, masked):
    return {
        "lines": text.count('\n') + 1,
        "funcs": len(re.findall(r'\bfunc\s+(?:\([^)]*\)\s*)?\w+\s*\(', masked)),
        "structs": len(STRUCT_DEF_RE.findall(masked)),
        "imports": _count_imports(text),
    }


def _count_imports(text):
    comments_only = mask_comments_only(text)
    block_match = IMPORT_BLOCK_RE.search(comments_only)
    if block_match:
        return len(IMPORT_LINE_RE.findall(block_match.group(1)))
    return len(IMPORT_SINGLE_RE.findall(comments_only))


def check_file_heuristic(path):
    print(f"\n=== Kiểm tra (heuristic): {path} ===")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        print(f"  [LỖI] Không thể đọc file: {e}")
        return False

    masked, mask_errors = mask_source(text)
    comments_only_masked = mask_comments_only(text)

    all_errors = []
    all_errors.extend(mask_errors)
    all_errors.extend(check_brackets(masked))
    all_errors.extend(check_package_declaration(masked))
    all_errors.extend(check_lone_brace(masked))
    all_errors.extend(check_top_level_short_decl(masked))
    all_errors.extend(check_unused_imports(masked, comments_only_masked))
    all_errors.extend(check_struct_literal_type_mismatch(masked))

    if all_errors:
        print(f"  Tìm thấy {len(all_errors)} vấn đề:")
        for e in all_errors:
            print(f"   - {e}")
    else:
        stats = gather_file_stats(text, masked)
        print("  OK: không phát hiện vấn đề nào ở các mục kiểm tra heuristic.")
        print(f"    Dòng: {stats['lines']} | func: {stats['funcs']} | "
              f"struct: {stats['structs']} | import: {stats['imports']}")
        print("    Đã qua: cân bằng ngoặc, chuỗi/rune/comment đóng đủ, khai báo package, "
              "vị trí '{', ':=' top-level, import không dùng, struct field type mismatch.")

    indent_warnings = check_indentation(text)
    if indent_warnings:
        n = len(indent_warnings)
        print(f"  [Cảnh báo, không phải lỗi] {n} dòng thụt lề bằng space thay vì tab. "
              f"Ví dụ dòng: {indent_warnings[:10]}" + (" ..." if n > 10 else ""))

    return len(all_errors) == 0


def collect_go_files(args):
    if not args:
        return sorted(glob.glob('**/*.go', recursive=True))
    files = []
    for a in args:
        if os.path.isdir(a):
            files.extend(sorted(glob.glob(os.path.join(a, '**/*.go'), recursive=True)))
        else:
            files.append(a)
    return files


def main():
    args = sys.argv[1:]

    real_go_result = try_real_go(args if args else ['.'])
    if real_go_result is not None:
        # đã dùng go thật -> xong
        sys.exit(0 if real_go_result else 1)

    print("[INFO] Không chạy được lệnh 'go version' (có thể chưa cài Go, hoặc go không "
          "khả dụng trong môi trường thực thi này) -> dùng chế độ heuristic "
          "(Python thuần, KHÔNG thể thay thế hoàn toàn go build/go vet).\n"
          "       Cài Go để có kết quả chính xác tuyệt đối: https://go.dev/dl/\n")

    files = collect_go_files(args)
    if not files:
        print("Không tìm thấy file .go nào để kiểm tra.")
        sys.exit(1)

    results = {}
    for path in files:
        if not os.path.isfile(path):
            print(f"\n=== {path} ===\n  [LỖI] File không tồn tại")
            results[path] = False
            continue
        results[path] = check_file_heuristic(path)

    print("\n=== Tổng kết ===")
    ok_count = sum(1 for v in results.values() if v)
    print(f"{ok_count}/{len(results)} file không có vấn đề (theo heuristic checker).")
    print("\nNhắc lại: đây vẫn là kiểm tra tĩnh dựa trên heuristic, không phải type-checker")
    print("đầy đủ. Để chắc chắn 100%, hãy cài Go rồi chạy 'go build ./...' và 'go vet ./...'.")

    sys.exit(0 if all(results.values()) else 1)


if __name__ == '__main__':
    main()

