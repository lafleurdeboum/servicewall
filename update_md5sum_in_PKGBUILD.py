import hashlib


PKGBUILD = "../AUR/PKGBUILD"

def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

def do_md5_sum(filename):
    new_sum = md5sum(filename)
    print(new_sum)

    with open(PKGBUILD) as pkg_file:
        sheet = pkg_file.read()

    for line in sheet.split("\n"):
        if "md5sums" in line:
            old_sum = eval(line.split("=")[1])
            print(old_sum)
            break

    if old_sum == new_sum:
        raise SystemExit

    with open(PKGBUILD, "w") as pkg_file:
        pkg_file.write(sheet.replace(old_sum, new_sum))
